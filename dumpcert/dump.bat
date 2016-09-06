# This extracts the client key from the client keystore

java -jar dump.jar 02221224710.jks senha1234567890##123 02221224710 > 02221224710.pkcs8

# This creates a client.p12 file that can be used by Firefox
# keytool -importkeystore -srckeystore 02221224710.jks -destkeystore 02221224710.p12 -deststoretype PKCS12 -srcalias 02221224710 -deststorepass senha1234567890##123 -destkeypass senha1234567890##123