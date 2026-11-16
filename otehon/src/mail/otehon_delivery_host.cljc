(ns mail.otehon-delivery-host
  "Trusted local host for private mail delivery."
  (:require [awai.otehon-delivery-host :as delivery]
            [awai.kotobase-block-adapter :as blocks]))

(defn bind!
  "Bind local Passkey and dango checks. The caller authenticates the address
   bindings, policy, signed basis, recipient grants and byte count."
  [host db credential-id holder]
  (delivery/bind! host db credential-id holder 65536))

(defn client!
  "Construct the ciphertext client with the host's broker and abort signal.
   Loopback HTTP is for explicit tests; production requires false and the
   reviewed canonical operation broker. This is not an SMTP transport."
  [origin broker get-selector put-selector signal allow-loopback-for-tests?]
  (blocks/client origin broker get-selector put-selector signal allow-loopback-for-tests?))
