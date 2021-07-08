<h1>pdm cryptography core module</h1>
<p>
This a commandl line encryption tool for linux and macOS, for windwos version please visit my other repository, <a href="https://github.com/2042Third/pdm-crypt-win">pdm-crypt-win</a>
</p>
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
<h2>benchmark:</h2>
<dl>
<dt>for a 2 gb video file, reading and writing to disk </dt>
<dd>20 round chacha20: ~5.1sec </dd>
<dd>12 round chacha20: ~3.10sec </dd>
  <dl>
<h2>usage:</h2>
<p>
goto src folder<br />
run shall script "sh build_t"<br />
edit short.sh to setup a encryption and decryption to disk.<br />
</p>
<p>
encrypted files have ORIGINAL_FILE.pdm pattern<br />
decrypted files have dec-ORIGINAL_FILE pattern<br />
</p>

