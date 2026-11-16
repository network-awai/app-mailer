(ns mail.browser-delivery-host
  "Browser-side trusted host composition; no Node credential store."
  (:require [awai.browser-delivery-host :as delivery] [awai.browser-local-revocations :as local] [awai.browser-dango-read-approval :as read] [awai.browser-dango-revocation-approval :as revoke]
            [awai.browser-block-authorization :as authorization] [awai.kotobase-block-adapter :as blocks]
            ))
(defn- with-delivery [bound {:keys [policy! identity-origin tenant-id audience broker signal allow-loopback-for-tests?
                                     now! interact! start-selector redeem-selector get-selector put-selector]}]
  (let [authorize! (authorization/authorizer
                     {:current! (:delivery-current! bound) :now! now! :interact! interact!}
                     policy! identity-origin tenant-id audience broker start-selector redeem-selector signal allow-loopback-for-tests?)]
    {:host (assoc bound :authorization! authorize!)
     :client (blocks/client audience broker get-selector put-selector signal allow-loopback-for-tests?)}))

(defn read-approved-delivery!
  "The host independently authenticates credentials, policy and local
   revocations and provides direct user interaction and a canonical broker.
   This function neither enrolls a Passkey nor grants broker consent."
  [host trust credential-db binding
   {:keys [client-origin read-now! read-interact! read-start-selector read-redeem-selector
           identity-origin tenant-id audience broker signal allow-loopback-for-tests?
           policy! now! interact! start-selector redeem-selector get-selector put-selector] :as options}]
  (let [client (read/client
                 {:client-origin client-origin :current! (:delivery-current! host) :now! read-now!
                  :admit! (fn [expected wire]
                            (when-not (= tenant-id (:tenant-id expected)) (throw (ex-info "Mail tenant refused" {})))
                            (delivery/bind! host trust wire credential-db binding 65536))}
                 identity-origin broker read-start-selector read-redeem-selector signal allow-loopback-for-tests?)]
    (-> (read/request! client tenant-id read-interact!)
        (.then (fn [bound] (with-delivery bound options))))))

(defn read-approved-local-delivery!
  "Bind trusted local revocation state before requesting the signed snapshot.
   The host still authenticates the scope, credential, policy and user consent."
  [host trust credential-db binding local-db scope options]
  (-> (local/bind-host! local-db scope host)
      (.then (fn [bound] (read-approved-delivery! bound trust credential-db binding options)))))


(defn revoke-approved-local-delivery!
  "Revoke one selected CID through the trusted identity interaction and bind
   the independently verified snapshot to Mail's existing local authority."
  [host trust credential-db binding local-db scope cid
   {:keys [client-origin read-now! identity-origin tenant-id broker signal allow-loopback-for-tests?
           revoke-start-selector revoke-redeem-selector revoke-interact!] :as options}]
  (-> (local/bind-host! local-db scope host)
      (.then (fn [local-host]
        (let [client (revoke/client
                       {:client-origin client-origin :current! (:delivery-current! local-host) :now! read-now!
                        :admit! (fn [expected wire]
                                  (when-not (= {:tenant-id tenant-id :cid cid} expected)
                                    (throw (ex-info "Mail revocation scope refused" {})))
                                  (delivery/bind! local-host trust wire credential-db binding 65536))}
                       identity-origin broker revoke-start-selector revoke-redeem-selector signal allow-loopback-for-tests?)]
          (-> (revoke/request! client tenant-id cid revoke-interact!)
              (.then (fn [bound] (with-delivery bound options)))))))))
