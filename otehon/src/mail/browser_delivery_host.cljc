(ns mail.browser-delivery-host
  "Browser-side trusted host composition; no Node credential store."
  (:require [awai.browser-delivery-host :as delivery] [awai.browser-dango-read-approval :as read]
            [awai.browser-block-authorization :as authorization] [awai.kotobase-block-adapter :as blocks]))
(defn read-approved-delivery!
  "The host independently authenticates credentials, policy and local
   revocations and provides direct user interaction and a canonical broker.
   This function neither enrolls a Passkey nor grants broker consent."
  [host trust credential-db binding
   {:keys [client-origin read-now! read-interact! read-start-selector read-redeem-selector
           identity-origin tenant-id audience broker signal allow-loopback-for-tests?
           policy! now! interact! start-selector redeem-selector get-selector put-selector]}]
  (let [client (read/client
                 {:client-origin client-origin :current! (:delivery-current! host) :now! read-now!
                  :admit! (fn [expected wire]
                            (when-not (= tenant-id (:tenant-id expected)) (throw (ex-info "Mail tenant refused" {})))
                            (delivery/bind! host trust wire credential-db binding 65536))}
                 identity-origin broker read-start-selector read-redeem-selector signal allow-loopback-for-tests?)]
    (-> (read/request! client tenant-id read-interact!)
        (.then (fn [bound]
          (let [authorize! (authorization/authorizer
              {:current! (:delivery-current! bound) :now! now! :interact! interact!}
              policy! identity-origin tenant-id audience broker start-selector redeem-selector signal allow-loopback-for-tests?)]
            {:host (assoc bound :authorization! authorize!)
             :client (blocks/client audience broker get-selector put-selector signal allow-loopback-for-tests?)}))))))
