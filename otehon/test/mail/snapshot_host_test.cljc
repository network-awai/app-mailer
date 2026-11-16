(ns mail.snapshot-host-test
  (:require [mail.otehon-delivery-host :as product] [awai.passkey-store :as store]
            [awai.dango-local-revocations :as local] [awai.browser-dango-watermark :as watermark]
            [awai.otehon-passkey :as otehon] [webauthn.virtual-authenticator :as virtual]
            [webauthn.adapters.edge :as edge] [envelope.keystore :as keys]
            [dango.chain :as dango] [ed25519.sign :as ed] ["fake-indexeddb" :refer [indexedDB]]
            ["@noble/curves/ed25519.js" :refer [ed25519]] ["@noble/hashes/sha2.js" :refer [sha256]]
            ["node:fs" :as fs] ["node:path" :as path]))
(defn check [x] (when-not x (throw (js/Error. "Mail snapshot host test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f) (.then (fn [_] false) (fn [_] true))))
(def tenant "did:key:zTenant") (def resource "kotoba://storage/post") (def signing (js/Uint8Array.from (range 32)))
(def roots #{(vec (array-seq (.getPublicKey ed25519 signing)))})
(defn payload [x] (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js x))))
(defn signed [ids]
  (let [n (count ids)] {:version 1 :tenant tenant :revision n :issuedAt 100 :expiresAt 130 :cids ids
    :signature (.toString (js/Buffer.from (.sign ed25519 (payload ["awai/dango-revocations/v1" tenant n 100 130 ids]) signing)) "base64url")}))
(def dir (.resolve path ".agent-output" (str "mail-snapshot-" (.randomUUID js/crypto))))
(.mkdirSync fs dir #js {:recursive true :mode 448})
(def db (store/open-owned! (.join path dir "credentials.sqlite")))
(local/initialize-storage! db) (local/initialize-scope! db "post")
(def idb (atom nil)) (def read-calls (atom []))
(defn selector [op] #js {:capability "identity" :service "authn" :operation op})
(defn read-options []
  (let [broker #js {"invoke" (fn [sel request _]
                  (let [url (.-input request) op (.-operation sel)
                        value (if (= op "read-start")
                                {:id (apply str (repeat 43 "a")) :secret (apply str (repeat 43 "b")) :expires-at 400000}
                                (signed []))
                        response (js/Response. (js/JSON.stringify (clj->js value)) #js {:status 201})]
                    (swap! read-calls conj op) (js/Object.defineProperty response "url" #js {:value url})
                    (js/Promise.resolve response)))}]
    {:client-origin "https://client.example" :read-now! (fn [] 100000) :now! (fn [] 100000)
     :identity-origin "https://identity.example" :tenant-id "t_abcdefghijkl" :audience "https://peer.example"
     :broker broker :signal (.-signal (js/AbortController.)) :allow-loopback-for-tests? false
     :read-start-selector (selector "read-start") :read-redeem-selector (selector "read-redeem")
     :start-selector (selector "block-start") :redeem-selector (selector "block-redeem")
     :get-selector (selector "get") :put-selector (selector "put")
     :policy! (fn [] {}) :interact! (fn [_] true) :read-interact! (fn [v] (check (not (contains? v :secret))) true)}))
(-> (watermark/open! indexedDB (str "awai-dango-revocation-" (.randomUUID js/crypto)))
    (.then (fn [x] (reset! idb x) (watermark/initialize! x tenant 0 (vec (array-seq (sha256 (payload [tenant 0 []])))) #{})))
    (.then (fn [_] (js/Promise.all #js [(virtual/create! "awai.network") (keys/generate-identity)])))
    (.then (fn [[auth key]]
      (let [public (edge/bytes->b64 (:public-key auth)) holder (otehon/account-did public) seed (vec (repeat 32 9))
            grant (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 10))
                    :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []}))
            target (first (:dango/cids (dango/verify grant {:roots #{(ed/public-key seed)} :revoked #{}
                    :request {:req/kind :data/read :req/resource resource :req/holder holder :req/now 100 :req/bytes 1}})))
            _ (store/enroll-trusted! db {:credential-id (:credential-id auth) :public-key-b64 public
                                         :holder holder :fingerprint (:recipient-key key) :sign-count 0})
            raw {:resource resource :now! (fn [] 100) :local-revocation-scope "post"
                 :policy! (fn [] {:roots #{(ed/public-key seed)} :revoked #{} :fresh-until 150 :bindings {holder (:recipient-key key)}})
                 :delivery-grants! (fn [] {:byte-count 1 :recipients [{:holder holder :presentation grant :fingerprint (:recipient-key key)}]})
                 :delivery-current! (fn [] true) :admit-cid! (fn [& _] true)}
            trust {:tenant tenant :roots roots :now! (fn [] 100) :db @idb} old (atom nil)]
        (-> (denied #(product/bind-snapshot! raw db (:credential-id auth) holder (assoc trust :roots #{(vec (repeat 32 7))}) (signed [])))
            (.then (fn [v] (check v) (product/bind-snapshot! raw db (:credential-id auth) holder trust (signed []))))
            (.then (fn [host] (reset! old host) (check (true? ((:delivery-current! host))))
                     (let [opts (read-options)]
                       (-> (denied #(product/read-approved-delivery! raw db (:credential-id auth) holder trust
                                      (assoc opts :read-interact! (fn [_] false))))
                           (.then (fn [rejected] (check rejected) (check (= ["read-start"] @read-calls))
                                    (product/read-approved-delivery! raw db (:credential-id auth) holder trust opts)))
                           (.then (fn [result] (check (fn? (get-in result [:host :delivery-current-async!])))
                                    (check (= ["read-start" "read-start" "read-redeem"] @read-calls))
                                    (product/bind-snapshot! raw db (:credential-id auth) holder trust (signed [target]))))))))
            (.then (fn [host] (check (false? ((:delivery-current! host)))) ((:delivery-current-async! @old))))
            (.then (fn [live] (check (false? live)) true))))))
    (.then (fn [_] (.close db) (.close @idb) (println (js/JSON.stringify #js {:passed true :scope "Mail signed dango delivery host"}))))
    (.catch (fn [e] (.close db) (when @idb (.close @idb)) (js/console.error e) (set! (.-exitCode js/process) 1))))
