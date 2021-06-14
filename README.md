pdm cryptography core module<br /><br />
CURRENT STATUS:<br />
disabled sha3 checking<br />
using boost thread (stl pthread also avaliable)<br />
hardcoded nonce (random generator is setup)<br />

<br />
usage:<br />
goto src folder<br />
run shall script "sh build_t"<br />
edit short.sh to setup a encryption and decryption to disk.<br />
<br />encrypted files have ORIGINAL_FILE.pdm pattern<br />
decrypted files have dec-ORIGINAL_FILE pattern<br />
<br />
benchmark:<br />
for a 6 gb video file, reading and writing to disk <br />
20 round chacha20: ~34sec / ~180 mb/sec<br />
12 round chacha20: ~30sec <br />
