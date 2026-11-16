(ns mail.otehon-delivery-host
  "Trusted local host for private mail delivery."
  (:require [awai.otehon-delivery-host :as delivery]))

(defn bind!
  "Bind local Passkey and dango checks. The caller authenticates the address
   bindings, policy, signed basis, recipient grants and byte count."
  [host db credential-id holder]
  (delivery/bind! host db credential-id holder 65536))
