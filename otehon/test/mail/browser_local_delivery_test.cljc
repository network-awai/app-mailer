(ns mail.browser-local-delivery-test
  (:require [mail.browser-delivery-host :as browser] [awai.browser-credential-binding :as credential] [awai.browser-local-revocations :as local] [multiformats.core :as mf]
            [awai.browser-dango-watermark :as watermark] [awai.browser-async-authority :as authority]
            [dango.chain :as dango] [ed25519.sign :as ed] ["fake-indexeddb" :refer [indexedDB]]
            ["@noble/curves/ed25519.js" :refer [ed25519]] ["@noble/hashes/sha2.js" :refer [sha256]]))
(defn check [x] (when-not x (throw (js/Error. "browser delivery host test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f) (.then (fn [_] false) (fn [_] true))))
(def tenant "did:key:zTenant") (def holder "did:key:zHolder") (def resource "kotoba://storage/test")
(def fp (str "kv1:" (apply str (repeat 43 "a")))) (def b {:credential-id "cred" :holder holder :fingerprint fp})
(def seed (js/Uint8Array.from (range 32))) (def grant-seed (vec (repeat 32 9)))
(def root (vec (array-seq (.getPublicKey ed25519 seed))))
(def grant (dango/present (dango/root {:issuer-seed grant-seed :next-seed (vec (repeat 32 10))
              :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []})))
(defn payload [x] (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js x))))
(def wire {:version 1 :tenant tenant :revision 0 :issuedAt 100 :expiresAt 130 :cids []
 :signature (.toString (js/Buffer.from (.sign ed25519 (payload ["awai/dango-revocations/v1" tenant 0 100 130 []]) seed)) "base64url")})
(def digest (vec (array-seq (sha256 (payload [tenant 0 []])))))
(defn selector [op] #js {:capability "identity" :service "authn" :operation op})
(def read-calls (atom []))
(def broker #js {"invoke" (fn [sel req _] (let [op (.-operation sel) url (.-input req)
  value (if (= op "read-start") {:id (apply str (repeat 43 "a")) :secret (apply str (repeat 43 "b")) :expires-at 400000} wire)
  r (js/Response. (js/JSON.stringify (clj->js value)) #js {:status 201})]
  (swap! read-calls conj op) (js/Object.defineProperty r "url" #js {:value url}) (js/Promise.resolve r)))})
(def opts {:client-origin "https://client.example" :read-now! (fn [] 100000) :now! (fn [] 100000)
 :identity-origin "https://identity.example" :tenant-id "t_abcdefghijkl" :audience "https://peer.example" :broker broker
 :signal (.-signal (js/AbortController.)) :allow-loopback-for-tests? false :read-interact! (fn [_] true)
 :read-start-selector (selector "read-start") :read-redeem-selector (selector "read-redeem")
 :start-selector (selector "block-start") :redeem-selector (selector "block-redeem")
 :get-selector (selector "get") :put-selector (selector "put") :policy! (fn [] {}) :interact! (fn [_] true)})
(def l* (atom nil)) (def local-cid (mf/cidv1-dag-cbor (js/Uint8Array.from #js [1 2 3])))
(def w* (atom nil)) (def c* (atom nil)) (def calls (atom 0))
(-> (local/open! indexedDB (str "awai-local-dango-" (.randomUUID js/crypto)))
    (.then (fn [db] (reset! l* db) (local/initialize! db "scope")))
    (.then (fn [_] (watermark/open! indexedDB (str "awai-dango-revocation-" (.randomUUID js/crypto)))))
    (.then (fn [db] (reset! w* db) (watermark/initialize! db tenant 0 digest #{})))
    (.then (fn [_] (credential/open! indexedDB (str "awai-credential-binding-" (.randomUUID js/crypto)))))
    (.then (fn [db] (reset! c* db) (credential/initialize! db b)))
    (.then (fn [_]
      (let [raw {:resource resource :now! (fn [] 100) :policy! (fn [] {:roots #{(ed/public-key grant-seed)} :revoked #{}
                    :bindings {holder fp} :fresh-until 150})
                 :delivery-current! (fn [] true)
                 :delivery-grants! (fn [] {:byte-count 1 :recipients [{:holder holder :presentation grant :fingerprint fp}]})
                 :admit-cid! (fn [& _] true)}
            trust {:tenant tenant :roots #{root} :now! (fn [] 100) :db @w*}]
        (-> (denied #(browser/read-approved-local-delivery! raw trust @c* b @l* "missing" opts))
            (.then (fn [x] (check x) (check (empty? @read-calls))
                     (denied #(browser/read-approved-local-delivery! raw trust @c* b @l* "scope" (assoc opts :read-interact! (fn [_] false))))))
            (.then (fn [x] (check x) (check (= ["read-start"] @read-calls))
                     (denied #(browser/read-approved-local-delivery! raw trust @c* (assoc b :holder "did:key:zOther") @l* "scope" opts))))
            (.then (fn [x] (check x) (browser/read-approved-local-delivery! raw trust @c* b @l* "scope" opts)))
            (.then (fn [result]
              (let [host (:host result)]
              (check (true? ((:delivery-current! host))))
              (let [client (authority/guard-client {:get-block (fn [_] (swap! calls inc) (js/Promise.resolve true))
                                                    :put-block! (fn [& _] (swap! calls inc) (js/Promise.resolve true))}
                                                   (:delivery-current-async! host))]
                (-> ((:get-block client) "cid")
                    (.then (fn [_] (check (= 1 @calls)) (-> (local/revoke-if! @l* "scope" local-cid (fn [] true)) (.then (fn [_] (denied #((:get-block client) "cid")))))))
                    (.then (fn [x] (check x) (check (= 1 @calls)) (credential/revoke! @c* b)))
                    (.then (fn [_] (denied #((:get-block client) "cid"))))
                    (.then (fn [x] (check x) (check (= 1 @calls)))))))))))))
    (.then (fn [_] (.close @l*) (.close @w*) (.close @c*) (println (js/JSON.stringify #js {:passed true :scope "Mail browser local revocation delivery"}))))
    (.catch (fn [e] (when @l* (.close @l*)) (when @w* (.close @w*)) (when @c* (.close @c*)) (js/console.error e) (set! (.-exitCode js/process) 1))))
