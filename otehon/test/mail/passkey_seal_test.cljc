(ns mail.passkey-seal-test
  (:require ["node:crypto" :as crypto] ["node:fs" :as fs] ["node:path" :as path]
            [mail.private-mail :as mail]
            [awai.passkey-store :as store] [awai.recipient-proof-store :as persisted] [awai.otehon-passkey :as otehon]
            [dango.chain :as dango] [ed25519.sign :as ed] [envelope.keystore :as keys] [envelope.seal :as seal]
            [webauthn.adapters.edge :as edge] [webauthn.virtual-authenticator :as virtual]))
(defn check [x] (when-not x (throw (js/Error. "browser recipient envelope test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f)
                     (.then (fn [_] (throw (js/Error. "unexpected acceptance"))) (fn [_] true))))
(defn ab [s] (.-buffer (js/Uint8Array.from (edge/b64url->bytes s))))
(def dir (.resolve path "../../.agent-output" (str "browser-recipient-envelope-" (.randomUUID crypto))))
(.mkdirSync fs dir #js {:mode 448})
(def db (store/open-owned! (.join path dir "credentials.sqlite")))
(persisted/initialize! db)
(def resource "kotoba://storage/browser-recipient")
(def seed (vec (repeat 32 3)))
(-> (js/Promise.all #js [(virtual/create! "awai.network") (keys/generate-identity) (keys/generate-identity)])
    (.then (fn [[auth identity sender-key]]
      (let [pub (edge/bytes->b64 (:public-key auth)) holder (otehon/account-did pub)
            _ (store/enroll-trusted! db {:credential-id (:credential-id auth) :public-key-b64 pub
                                         :holder holder :fingerprint (:recipient-key identity) :sign-count 0})
            clock (fn [] 100) issued (persisted/issue! db (:credential-id auth) clock)
            recipient-host (persisted/host db (:credential-id auth) (:nonce issued) "awai.network" "https://awai.network"
                                           clock (fn [h] (when (= h holder) (:recipient-key identity))))
            calls (atom 0)
            request! (fn [options]
              (swap! calls inc)
              (check (= "required" (.. options -publicKey -userVerification)))
              (check (= 1 (.-length (.. options -publicKey -allowCredentials))))
              (let [challenge (seal/b64url (.. options -publicKey -challenge))]
                (-> ((:assert! auth) {:origin "https://awai.network" :challenge challenge :sign-count 1})
                    (.then (fn [assertion]
                      #js {:type "public-key" :id (:credential-id auth) :rawId (ab (:credential-id auth))
                           :response #js {:clientDataJSON (ab (:client-data-json-b64url assertion))
                                          :authenticatorData (ab (:authenticator-data-b64url assertion))
                                          :signature (ab (:signature-b64url assertion))}})))))
            presentation (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 4))
                           :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []}))
            sender "did:key:sender"
            sender-presentation (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 5))
                                 :grant {:caps #{[:data/read resource]} :holder sender :before 200} :caveats []}))
            others [{:holder sender :presentation sender-presentation :pub (:pub sender-key) :pq-pub (:pq-pub sender-key)}]
            address-bindings (atom {"alice@example.test" sender "bob@example.test" holder})
            message {:schema "awai.mail/private-message-v1" :id "mail-1" :author sender :from "alice@example.test" :to ["bob@example.test"] :cc [] :subject "private" :text "hello" :sent-at 100 :in-reply-to nil}
            host {:recipient-host recipient-host :request! request! :resource resource :now! clock :author sender :bindings! (fn [] @address-bindings)
                  :policy! (fn [] {:roots #{(ed/public-key seed)} :revoked #{} :fresh-until 150
                                    :bindings {sender (:recipient-key sender-key)}})}
            nonce (edge/b64url->bytes (:nonce issued))]
        (-> (denied #(mail/prepare-passkey-seal! host (assoc message :to ["mallory@example.test"]) nonce (:pub identity) (:pq-pub identity) presentation others))
            (.then (fn [_] (check (zero? @calls))
                     (mail/prepare-passkey-seal! host message nonce (:pub identity) (:pq-pub identity) presentation others)))
            (.then (fn [prepared]
              (check (= [holder sender] (:recipients prepared)))
              (let [pending ((:confirm! prepared))]
                (check (= 1 @calls))
                (-> pending
                    (.then (fn [sealed]
                      (js/Promise.all #js [(mail/open! (assoc host :admit! (fn [_ _] true)) sealed
                                             {:resource resource :recipients #{holder sender} :author sender :id "mail-1"} holder identity)
                                           (mail/open! (assoc host :admit! (fn [_ _] true)) sealed
                                             {:resource resource :recipients #{holder sender} :author sender :id "mail-1"} sender sender-key)])))
                    (.then (fn [opened] (doseq [plain (array-seq opened)]
                                          (check (= message plain)))
                             (denied #((:confirm! prepared)))))))))))))
    (.then (fn [_] (.close db) (println (js/JSON.stringify #js {:passed true :scope "synthetic Mail address bindings and recipient Passkey proof"}))))
    (.catch (fn [e] (.close db) (js/console.error e) (set! (.-exitCode js/process) 1))))
