(ns mail.private-mail-test
  (:require [mail.private-mail :as message] [dango.chain :as dango]
            [ed25519.sign :as ed] [envelope.keystore :as keys]
            [envelope.seal-sync :as crypto]))
(defn check [v] (when-not v (throw (js/Error. "private mail test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f)
                     (.then (fn [_] (throw (js/Error. "unexpected message approval"))) (fn [_] true))))
(def seed (vec (repeat 32 1)))
(def resource "kotoba://storage/synthetic-private-post")
(def sender "did:key:synthetic-sender")
(def reader "did:key:synthetic-reader")
(def a (crypto/generate-hybrid-recipient))
(def b (crypto/generate-hybrid-recipient))
(defn recipient [holder key next-seed]
  {:holder holder :pub (:pub key) :pq-pub (:pq-pub key)
   :presentation (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 next-seed))
                    :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []}))})
(def recipients [(recipient sender a 2) (recipient reader b 3)])
(def msg {:schema "awai.mail/private-message-v1" :id "p1" :author sender :from "alice@example.test" :to ["bob@example.test"] :cc [] :subject "private synthetic subject" :text "private synthetic mail" :sent-at 100 :in-reply-to nil})
(-> (js/Promise.all #js [(keys/fingerprint a) (keys/fingerprint b)])
    (.then (fn [[afp bfp]]
      (let [policy {:roots #{(ed/public-key seed)} :revoked #{} :fresh-until 150 :bindings {sender afp reader bfp}}
            bindings {"alice@example.test" sender "bob@example.test" reader}
            host {:author sender :resource resource :bindings! (fn [] bindings) :now! (fn [] 100) :policy! (fn [] policy)}
            decision (dango/verify (:presentation (second recipients))
                       {:roots (:roots policy) :revoked #{}
                        :request {:req/kind :data/read :req/resource resource :req/holder reader :req/now 100}})
            revoked-cid (first (:dango/cids decision))
            expected {:resource resource :recipients #{sender reader} :author sender :id "p1"}
            admit {:author sender :bindings! (fn [] bindings) :admit! (fn [e _] (= e expected))}]
        (-> (message/seal! host msg recipients)
            (.then (fn [sealed]
              (check (string? revoked-cid))
              (check (not (.includes (pr-str (:envelope sealed)) (:text msg))))
              (check (not (.includes (js/Buffer.from (first (:chunks sealed))) (:text msg) "utf8")))
              (check (not (.includes (js/Buffer.from (first (:chunks sealed))) (:subject msg) "utf8")))
              (-> (message/open! admit sealed expected reader (select-keys b [:priv :pq-priv]))
                  (.then (fn [opened] (check (= msg opened))
                    (js/Promise.all
                     #js [(denied #(message/seal! host (assoc msg :author reader) recipients))
                          (denied #(message/seal! host msg [(second recipients)]))
                          (denied #(message/seal! host msg [(first recipients)]))
                          (denied #(message/seal! host (assoc msg :to ["unknown@example.test"]) recipients))
                          (denied #(message/seal! host (assoc msg :bcc ["secret@example.test"]) recipients))
                          (denied #(message/seal! host (assoc msg :subject "bad\r\ninjected") recipients))
                          (denied #(let [calls (atom 0)] (message/seal! (assoc host :bindings! (fn [] (if (= 1 (swap! calls inc)) bindings (dissoc bindings "bob@example.test")))) msg recipients)))
                          (denied #(message/open! (assoc admit :bindings! (fn [] (dissoc bindings "bob@example.test"))) sealed expected reader (select-keys b [:priv :pq-priv])))
                          (denied #(message/seal! (assoc host :policy! (fn [] (assoc policy :fresh-until 100))) msg recipients))
                          (denied #(let [calls (atom 0)]
                                     (message/seal! (assoc host :policy! (fn [] (if (= 1 (swap! calls inc)) policy
                                                                                   (assoc policy :revoked #{revoked-cid}))))
                                                    msg recipients)))
                          (denied #(let [chunk (js/Uint8Array.from (first (:chunks sealed)))]
                                     (aset chunk 0 (bit-xor 1 (aget chunk 0)))
                                     (message/open! admit (assoc sealed :chunks [chunk]) expected reader (select-keys b [:priv :pq-priv]))))
                          (denied #(message/open! admit sealed (assoc expected :id "other") reader (select-keys b [:priv :pq-priv])))
                          (denied #(message/open! admit sealed (assoc expected :author reader) reader (select-keys b [:priv :pq-priv])))
                          (denied #(message/open! admit sealed expected reader (select-keys a [:priv :pq-priv])))]))))))))))
    (.then (fn [_] (println (js/JSON.stringify #js {:passed true :scope "synthetic private mail address binding and policy"}))))
    (.catch (fn [e] (js/console.error e) (set! (.-exitCode js/process) 1))))
