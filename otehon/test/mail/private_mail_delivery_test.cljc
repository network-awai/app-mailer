(ns mail.private-mail-delivery-test
  (:require [mail.private-mail :as mail] [awai.browser-shared-object :as wire]
            [dango.chain :as dango] [ed25519.sign :as ed]
            [envelope.keystore :as keys] [envelope.seal :as seal] [envelope.seal-sync :as crypto]
            [multiformats.core :as mf]))

(defn check [x] (when-not x (throw (js/Error. "private mail delivery test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f)
                     (.then (fn [_] (throw (js/Error. "unexpected delivery"))) (fn [_] true))))
(def seed (vec (repeat 32 1)))
(def resource "kotoba://storage/synthetic-mail")
(def sender "did:key:sender")
(def reader "did:key:reader")
(def a (crypto/generate-hybrid-recipient))
(def b (crypto/generate-hybrid-recipient))
(defn grant [holder key n]
  {:holder holder :pub (:pub key) :pq-pub (:pq-pub key)
   :presentation (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 n))
                   :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []}))})
(def value {:schema "awai.mail/private-message-v1" :id "mail-1" :author sender
            :from "alice@example.test" :to ["bob@example.test"] :cc [] :subject "secret subject"
            :text "private mail delivery" :sent-at 100 :in-reply-to nil})
(def expected {:resource resource :recipients #{sender reader} :author sender :id "mail-1"})
(defn clone [b] (js/Uint8Array.from b))

(-> (js/Promise.all #js [(keys/fingerprint a) (keys/fingerprint b)])
    (.then (fn [[afp bfp]]
      (let [policy {:roots #{(ed/public-key seed)} :revoked #{} :fresh-until 150 :bindings {sender afp reader bfp}}
            bindings (atom {"alice@example.test" sender "bob@example.test" reader})
            sealing {:author sender :resource resource :bindings! #(deref bindings) :now! (fn [] 100) :policy! (fn [] policy)}
            stored (atom {}) writes (atom 0) current (atom true) allowed (atom nil) fingerprints (atom {sender afp reader bfp})
            client {:put-block! (fn [cid bytes auth] (check (= auth "Biscuit synthetic")) (swap! writes inc)
                                  (swap! stored assoc cid (clone bytes)) (js/Promise.resolve cid))
                    :get-block (fn [cid] (js/Promise.resolve (some-> (get @stored cid) clone)))}
            host {:author sender :resource resource :bindings! #(deref bindings) :delivery-current! #(deref current) :delivery-current-async! (fn [] (js/Promise.resolve @current))
                  :delivery-fingerprints! #(deref fingerprints)
                  :admit-cid! (fn [cid basis] (and (= cid @allowed) (= expected basis)))
                  :authorization! (fn [_] (js/Promise.resolve "Biscuit synthetic"))
                  :admit! (fn [basis _] (= expected basis))}]
        (-> (mail/seal! sealing value [(grant sender a 2) (grant reader b 3)])
            (.then (fn [sealed]
              (let [cid (mf/cidv1-raw (wire/encode sealed))]
                (reset! allowed cid)
                (-> (denied #(mail/publish! host client sealed (assoc expected :id "other") value))
                    (.then (fn [_] (denied #(mail/publish! host client
                                   (assoc-in sealed [:envelope :envelope/recipients 1 :recipient/pub] (seal/b64url (js/Uint8Array. 32))) expected value))))
                    (.then (fn [_] (check (zero? @writes)) (mail/publish! host client sealed expected value)))
                    (.then (fn [published]
                      (check (= cid published)) (check (= 1 @writes))
                      (let [raw (js/Buffer.from (get @stored cid))]
                        (check (not (.includes raw (:text value)))) (check (not (.includes raw (:subject value)))))
                      (mail/receive! host client cid expected reader (select-keys b [:priv :pq-priv]))))
                    (.then (fn [opened] (check (= value opened))
                      (swap! bindings dissoc "bob@example.test")
                      (denied #(mail/receive! host client cid expected reader (select-keys b [:priv :pq-priv])))))
                    (.then (fn [_] (swap! bindings assoc "bob@example.test" reader)
                      (let [revoking (assoc host :authorization! (fn [_] (reset! current false) (js/Promise.resolve "Biscuit synthetic")))]
                        (denied #(mail/publish! revoking client sealed expected value)))))
                    (.then (fn [_] (check (= 1 @writes)) (reset! current true)
                      (let [changed (assoc host :authorization! (fn [_] (swap! bindings dissoc "bob@example.test") (js/Promise.resolve "Biscuit synthetic")))]
                        (denied #(mail/publish! changed client sealed expected value)))))
                    (.then (fn [_] (check (= 1 @writes)) (swap! bindings assoc "bob@example.test" reader)
                      (let [rotating (assoc host :authorization! (fn [_] (swap! fingerprints assoc reader afp) (js/Promise.resolve "Biscuit synthetic")))]
                        (denied #(mail/publish! rotating client sealed expected value)))))
                    (.then (fn [_] (check (= 1 @writes)) (reset! fingerprints {sender afp reader bfp})
                      (let [calls (atom 0) changing (assoc host :admit! (fn [_ _] (= 1 (swap! calls inc))))]
                        (denied #(mail/receive! changing client cid expected reader (select-keys b [:priv :pq-priv]))))))
                    (.then (fn [_]
                      (let [bytes (clone (get @stored cid))]
                        (aset bytes 0 (bit-xor 1 (aget bytes 0))) (swap! stored assoc cid bytes)
                        (denied #(mail/receive! host client cid expected reader (select-keys b [:priv :pq-priv]))))))))))))))
    (.then (fn [_] (println (js/JSON.stringify #js {:passed true :scope "synthetic private mail block delivery and address binding"}))))
    (.catch (fn [error] (js/console.error error) (set! (.-exitCode js/process) 1))))
