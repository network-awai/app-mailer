(ns mail.passkey-seal-test
  (:require ["node:crypto" :as crypto] ["node:fs" :as fs] ["node:path" :as path] ["node:http" :as http]
            [mail.private-mail :as mail] [mail.otehon-delivery-host :as delivery]
            [awai.browser-shared-object :as wire] [multiformats.core :as mf]
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
(def stored (atom nil)) (def allowed (atom nil)) (def writes (atom 0)) (def operations (atom []))
(def server (http/createServer
  (fn [req res]
    (if (not= (.-url req) (str "/private-ipld/" @allowed))
      (do (.writeHead res 404) (.end res))
      (if (= "PUT" (.-method req))
        (let [parts (atom [])]
          (.on req "data" #(swap! parts conj %))
          (.on req "end" (fn []
            (check (= "Biscuit synthetic" (aget (.-headers req) "authorization")))
            (reset! stored (js/Buffer.concat (clj->js @parts))) (swap! writes inc)
            (.writeHead res 201) (.end res))))
        (if (and (= "GET" (.-method req)) @stored) (.end res @stored)
          (do (.writeHead res 404) (.end res))))))))
(def peer (js/Promise. (fn [resolve reject] (.once server "error" reject)
  (.listen server 0 "127.0.0.1" #(resolve (str "http://127.0.0.1:" (.-port (.address server))))))))
(-> (js/Promise.all #js [(virtual/create! "awai.network") (keys/generate-identity) (keys/generate-identity) peer])
    (.then (fn [[auth identity sender-key origin]]
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
            revoked (atom #{})
            expected {:resource resource :recipients #{holder sender} :author sender :id "mail-1"}
            byte-count (.-length (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js message))))
            host (delivery/bind!
                   {:recipient-host recipient-host :request! request! :resource resource :now! clock :author sender
                    :bindings! (fn [] @address-bindings)
                    :policy! (fn [] {:roots #{(ed/public-key seed)} :revoked @revoked :fresh-until 150
                                     :bindings {holder (:recipient-key identity) sender (:recipient-key sender-key)}})
                    :delivery-grants! (fn [] {:byte-count byte-count :recipients
                      [{:holder holder :presentation presentation :fingerprint (:recipient-key identity)}
                       {:holder sender :presentation sender-presentation :fingerprint (:recipient-key sender-key)}]})
                    :delivery-current! (fn [] true)
                    :admit-cid! (fn [cid basis] (and (= cid @allowed) (= expected basis)))
                    :admit! (fn [basis _] (= expected basis))
                    :authorization! (fn [_] (js/Promise.resolve "Biscuit synthetic"))}
                   db (:credential-id auth) holder)
            controller (js/AbortController.)
            broker #js {:invoke (fn [selector request options]
                      (swap! operations conj [(.-operation selector) (.. request -init -method)])
                      (js/fetch (.-input request) (js/Object.assign #js {:redirect "error" :signal (.-signal options)} (.-init request))))}
            client (delivery/client! origin broker #js {:operation "get"} #js {:operation "put"} (.-signal controller) true)
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
                      (reset! allowed (mf/cidv1-raw (wire/encode sealed)))
                      (mail/publish! host client sealed expected message)))
                    (.then (fn [cid] (check (= 1 @writes)) (check (not (.includes @stored (js/Buffer.from "hello"))))
                      (mail/receive! host client cid expected holder identity)))
                    (.then (fn [opened] (check (= message opened)) (check (= [["put" "PUT"] ["get" "GET"]] @operations))
                      (let [decision (dango/verify presentation {:roots #{(ed/public-key seed)} :revoked #{}
                           :request {:req/kind :data/read :req/resource resource :req/holder holder :req/now 100 :req/bytes byte-count}})]
                        (reset! revoked #{(first (:dango/cids decision))}))
                      (denied #(mail/receive! host client @allowed expected holder identity))))
                    (.then (fn [_] (reset! revoked #{}) (check (store/revoke! db (:credential-id auth)))
                      (denied #(mail/receive! host client @allowed expected holder identity))))
                    (.then (fn [_] (check (= 2 (count @operations))) (.abort controller)
                      (denied #((:confirm! prepared)))))))))))))
    (.then (fn [_] (.close server) (.close db) (println (js/JSON.stringify #js {:passed true :scope "Mail virtual Passkey and loopback Kotobase delivery"}))))
    (.catch (fn [e] (.close server) (.close db) (js/console.error e) (set! (.-exitCode js/process) 1))))
