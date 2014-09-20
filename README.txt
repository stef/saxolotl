salty axolotl implements the Axolotl ratched based on primitives found in DJBs
NaCL-derivate libsodium.

dependencies: SecureString, pysodium

example:

    # create 2 peers with long-term keys
    peer1 = Peer('peer1')
    peer2 = Peer('peer2')

    # create an axolotl context with the other peer
    ctx1 = AxolotlCTX(peer1)
    ctx2 = AxolotlCTX(peer2)

    # aspeer() extracts the public parameters to be given to the other peer
    # pairs up the context and sets up initial keys
    ctx1.init(ctx2.aspeer())
    ctx2.init(ctx1.aspeer())

    # sending/encrypt
    msg = ctx1.send("howdy")
    # does it look like plaintext?
    print repr(msg)
    # receiving/decrypt
    print peer1.name, 'sent', ctx2.recv(msg)
