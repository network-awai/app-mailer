(ns mail.otehon-delivery-host
  "Trusted local host for private mail delivery."
  (:require [awai.otehon-delivery-host :as delivery]
            [awai.browser-dango-snapshot :as dango-snapshot]
            [awai.browser-dango-read-approval :as dango-read]
            [awai.browser-block-authorization :as authorization]
            [awai.kotobase-block-adapter :as blocks]))

(defn bind!
  "Bind local Passkey and dango checks. The caller authenticates the address
   bindings, policy, signed basis, recipient grants and byte count."
  [host db credential-id holder]
  (delivery/bind-local-revocations! host db credential-id holder 65536 (:local-revocation-scope host)))

(defn client!
  "Construct the ciphertext client with the host's broker and abort signal.
   Loopback HTTP is for explicit tests; production requires false and the
   reviewed canonical operation broker. This is not an SMTP transport."
  [origin broker get-selector put-selector signal allow-loopback-for-tests?]
  (blocks/client origin broker get-selector put-selector signal allow-loopback-for-tests?))

(defn approved-delivery!
  "Construct the trusted local host, identity approval and peer client using
   the same peer origin, broker and lifetime signal. This is not SMTP."
  [host db credential-id holder {:keys [policy! now! interact! identity-origin tenant-id audience
                                         broker start-selector redeem-selector get-selector put-selector
                                         signal allow-loopback-for-tests?]}]
  (let [bound (bind! host db credential-id holder)
        authorize! (authorization/authorizer
                     {:current! (:delivery-current! bound) :now! now! :interact! interact!}
                     policy! identity-origin tenant-id audience broker start-selector redeem-selector signal
                     allow-loopback-for-tests?)]
    {:host (assoc bound :authorization! authorize!)
     :client (client! audience broker get-selector put-selector signal allow-loopback-for-tests?)}))

(defn bind-snapshot! [host db credential-id holder trust snapshot]
  (-> (dango-snapshot/bind-host! host trust snapshot)
      (.then (fn [verified] (bind! verified db credential-id holder)))))

(defn approved-snapshot-delivery! [host db credential-id holder trust snapshot options]
  (-> (dango-snapshot/bind-host! host trust snapshot)
      (.then (fn [verified] (approved-delivery! verified db credential-id holder options)))))

(defn read-approved-delivery!
  "Request an independently approved snapshot before constructing delivery.
   The trusted host supplies pinned snapshot roots and direct user interaction.
   Read start/redeem and block operations require separate broker approvals.
   This function supplies no consent UI, identity service or SMTP transport."
  [host db credential-id holder trust
   {:keys [client-origin read-now! read-interact! read-start-selector read-redeem-selector
           identity-origin tenant-id broker signal allow-loopback-for-tests?] :as options}]
  (let [client (dango-read/client
                 {:client-origin client-origin :current! (:delivery-current! host) :now! read-now!
                  :admit! (fn [expected snapshot]
                            (when-not (= tenant-id (:tenant-id expected))
                              (throw (ex-info "Mail tenant refused" {})))
                            (dango-snapshot/bind-host! host trust snapshot))}
                 identity-origin broker read-start-selector read-redeem-selector signal allow-loopback-for-tests?)]
    (-> (dango-read/request! client tenant-id read-interact!)
        (.then (fn [verified] (approved-delivery! verified db credential-id holder options))))))
