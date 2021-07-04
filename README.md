<h1>pdm cryptography core module</h1>
<h2>CURRENT STATUS:</h2>
enabled sha3 checking<br />
using boost thread (stl pthread also avaliable)<br />
<h2>updated 7/4/2021: </h2>
<dl>
<dt>Added features</dt>
<dd>installation script ("src/update-bin.sh") for macos and linux</dd>
<dd>completely random nonce generation</dd>
<dd>sha3 enabled</dd>
<dd>new command line interface</dd>
<dt>Fixes</dt>
  <dd>no repeated nonce</dd>
  <dd>disk reading is mostly serialized</dd>
  <dd>disk writing is completely serialized</dd>
  <dd>minor memory fixes</dd>
</dl>
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
