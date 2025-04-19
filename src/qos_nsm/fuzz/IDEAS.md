# Fuzzing Ideas

Special parameter requirements:
* Valid inputs for attestation doc related testing harnesses can be fairly large. For example, src/static/mock_attestation_doc is over 5KB in size. Therefore a relatively large `-min_len=` length parameter value such as `-min_len=6000` is needed during fuzzing.