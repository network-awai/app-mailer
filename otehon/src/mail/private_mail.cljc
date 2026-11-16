(ns mail.private-mail
  "Internal E2EE mail envelope. Not SMTP, OpenPGP, Bcc or a mail transport.
   A trusted user-side host supplies authenticated address/key bindings,
   current dango policy and independently verified sender/object admission."
  (:require [awai.browser-authorized-envelope :as envelope]
            [awai.browser-recipient-envelope :as recipient-envelope]
            [awai.delivery-key-binding :as key-binding]
            [awai.private-message-blocks :as blocks]))

(defn refuse [] (throw (ex-info "private mail refused" {})))
(defn- text? [x n] (and (string? x) (<= 1 (count x) n)))
(defn- address? [x]
  (and (text? x 254) (boolean (re-matches #"[^\s@<>]+@[^\s@<>]+" x))))
(defn- header? [x n]
  (and (string? x) (<= (count x) n) (not (re-find #"[\r\n]" x))))
(defn- expected? [expected]
  (and (map? expected) (= #{:resource :recipients :author :id} (set (keys expected)))
       (text? (:resource expected) 256) (set? (:recipients expected))
       (<= 1 (count (:recipients expected)) 32) (every? #(text? % 256) (:recipients expected))
       (text? (:author expected) 256) (contains? (:recipients expected) (:author expected))
       (text? (:id expected) 128)))
(defn- mail? [m]
  (and (map? m) (= #{:schema :id :author :from :to :cc :subject :text :sent-at :in-reply-to} (set (keys m)))
       (= "awai.mail/private-message-v1" (:schema m)) (text? (:id m) 128) (text? (:author m) 256)
       (address? (:from m)) (vector? (:to m)) (<= 1 (count (:to m)) 32)
       (vector? (:cc m)) (<= (count (:cc m)) 32)
       (every? address? (concat (:to m) (:cc m)))
       (= (count (concat (:to m) (:cc m))) (count (set (concat (:to m) (:cc m)))))
       (header? (:subject m) 998) (string? (:text m)) (<= (count (:text m)) 30000)
       (js/Number.isSafeInteger (:sent-at m)) (<= 0 (:sent-at m))
       (or (nil? (:in-reply-to m)) (and (text? (:in-reply-to m) 512) (header? (:in-reply-to m) 512)))))

(defn- addresses-authorized! [host mail recipient-ids]
  (let [bindings ((:bindings! host)) addresses (concat (:to mail) (:cc mail))
        holders (mapv #(get bindings %) addresses)]
    (when-not (and (map? bindings) (= (:author host) (:author mail))
                   (= (:author host) (get bindings (:from mail)))
                   (every? #(text? % 256) holders)
                   (= recipient-ids (conj (set holders) (:author host)))) (refuse))))

(defn prepare-passkey-seal!
  "Prepare one recipient's Passkey proof and the full independently bound
   recipient list. The trusted host must display the account, recipients and
   operation and invoke :confirm! directly from a user gesture. No network or
   SMTP operation is performed here."
  [host mail nonce pub pq-pub presentation others]
  (when-not (and (map? host) (text? (:author host) 256) (text? (:resource host) 256)
                 (fn? (:bindings! host)) (map? (:recipient-host host)) (mail? mail)
                 (vector? others) (every? map? others)) (refuse))
  (let [ids (conj (set (map :holder others)) (get-in host [:recipient-host :holder]))]
    (when-not (and (= (count ids) (inc (count others))) (contains? ids (:author host))) (refuse))
    (addresses-authorized! host mail ids)
    (-> (recipient-envelope/prepare! host nonce pub pq-pub presentation others)
        (.then (fn [prepared]
          (when-not (= ids (set (:recipients prepared))) (refuse))
          (assoc (dissoc prepared :confirm!) :confirm!
            (fn []
              (addresses-authorized! host mail ids)
              (let [plain (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js mail)))]
                (try
                  (-> ((:confirm! prepared) plain)
                      (.then (fn [sealed] (addresses-authorized! host mail ids) sealed))
                      (.finally (fn [] (.fill plain 0))))
                  (catch :default e (.fill plain 0) (throw e)))))))))))

(defn seal!
  "Only an independently authenticated host may provide :author, :resource,
   :bindings!, :policy! and :now!. Bindings are checked before and after seal;
   each recipient must also satisfy the shared dango and key-fingerprint gate."
  [host mail recipients]
  (when-not (and (map? host) (text? (:author host) 256) (text? (:resource host) 256)
                 (fn? (:bindings! host)) (mail? mail) (vector? recipients)
                 (every? map? recipients)) (refuse))
  (let [ids (set (map :holder recipients))
        _ (when-not (and (= (count ids) (count recipients)) (contains? ids (:author host))) (refuse))
        _ (addresses-authorized! host mail ids)
        plain (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js mail)))]
    (-> (js/Promise.resolve nil)
        (.then (fn [] (envelope/seal host (:resource host) plain recipients)))
        (.then (fn [sealed] (addresses-authorized! host mail ids) sealed))
        (.finally (fn [] (.fill plain 0))))))

(defn open!
  "Host :admit! independently verifies the exact sender, object and recipient
   set against a signed basis and current policy. :bindings! must be current and
   authenticated; message/peer data cannot supply it. No Bcc is supported."
  [host object expected recipient identity]
  (when-not (and (map? host) (fn? (:admit! host)) (fn? (:bindings! host))
                 (text? (:author host) 256) (expected? expected)
                 (= (:author host) (:author expected))) (refuse))
  (let [admit! (:admit! host)
        scoped (assoc host :admit! (fn [_ candidate] (admit! expected candidate)))]
    (-> (envelope/open scoped object (select-keys expected [:resource :recipients]) recipient identity)
        (.then (fn [plain]
          (try
            (let [mail (js->clj (js/JSON.parse (.decode (js/TextDecoder. "utf-8" #js {:fatal true}) plain))
                                :keywordize-keys true)]
              (when-not (and (mail? mail) (= (:id expected) (:id mail))
                             (= (:author expected) (:author mail))) (refuse))
              (addresses-authorized! host mail (:recipients expected))
              mail)
            (finally (.fill plain 0))))))))

(defn publish!
  "Publish an already sealed internal mail object against a host-authenticated
   CID and message basis. The client and each external-operation approval are
   supplied by the trusted runtime; this is not SMTP or address discovery."
  [host client object expected mail]
  (when-not (and (map? host) (expected? expected) (mail? mail) (fn? (:bindings! host))
                 (fn? (:delivery-current! host)) (= (:resource host) (:resource expected))
                 (= (:id mail) (:id expected)) (= (:author host) (:author expected) (:author mail))) (refuse))
  (let [current! (:delivery-current! host)
        scoped (assoc host :delivery-current!
                      (fn [] (try (and (true? (current!))
                                       (do (addresses-authorized! host mail (:recipients expected)) true))
                                  (catch :default _ false))))]
    (-> (key-binding/verify! scoped object expected)
        (.then (fn [bindings]
                 (blocks/publish! (key-binding/guarded-host scoped expected bindings) client object expected))))))

(defn receive!
  "Receive an authenticated mail object and open it while rechecking delivery
   authority, CID and the host's sender/basis admission. The existing open
   path checks current address bindings before releasing plaintext."
  [host client cid expected recipient identity]
  (when-not (and (map? host) (expected? expected) (= (:author host) (:author expected))
                 (fn? (:delivery-current! host)) (fn? (:admit-cid! host)) (fn? (:admit! host))) (refuse))
  (let [bindings (key-binding/capture! host expected)
        guarded (key-binding/guarded-host host expected bindings)]
    (-> (blocks/receive! guarded client cid expected)
        (.then (fn [object]
                 (-> (key-binding/verify! guarded object expected)
                     (.then (fn [actual]
                       (when-not (= actual bindings) (refuse))
                       (open! (assoc host :admit! (fn [scope candidate]
                                (and (true? ((:delivery-current! guarded)))
                                     (true? ((:admit-cid! host) cid expected))
                                     (true? ((:admit! host) scope candidate)))))
                              object expected recipient identity)))))))))
