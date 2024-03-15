# challenge
UDP packet challenge

payload_comparer.py will generate the following statistics to stdout:

- Total number of packets per side
- Number of packets in A without a corresponding counterpart in B, and vice versa
- Number of packets when A is faster than B, and vice versa
- Average speed advantage (time difference) per channel, conditioned on being the faster one

Parsing UDP packets is handled in payload_interface.py

Every function has a unit test, which can be seen with
`coverage html`

To run:

`python payload_comparer.py --directory_path {INSERT_DIR_PATH}`

To examine each UDP Payload for debugging purposes. A json file for each payload will be generated in the directory path: 

`python payload_comparer.py --directory_path {INSERT_DIR_PATH} --debug`
