const nacl = require('tweetnacl');
 nacl.util = require('tweetnacl-util');
 
  const username = 'odax'; // TODO: Replace with your username
 const github = octokit({ debug: true });
 const server = express();
 
 // Create application/x-www-form-urlencoded parser
 const urlencodedParser = bodyParser.urlencoded({ extended: false });
 
 // Generate an access token: https://github.com/settings/tokens

 // Set it to be able to create gists
 github.authenticate({
   type: 'oauth',
   token: process.env.GITHUB_TOKEN
 });
 
 // TODO:  Attempt to load the key from config.json.  If it is not found, create a new 32 byte key.
let keyPair;
let secretKey;
try {
  const data = fs.readFileSync('./config.json');

  // Read key from the file
  const keyObj = JSON.parse(data);
  secretKey = nacl.util.decodeBase64(keyObj.secretKey);
  keyPair = nacl.box.keyPair.fromSecretKey(secretKey);
} catch (err) {
  // Key was not in file
  // secretKey = nacl.randomBytes(32);
  keyPair = nacl.box.keyPair();
  secretKey = keyPair.secretKey;
 
  const keyObj = { secretKey: nacl.util.encodeBase64(secretKey) };

  // Writes to config.json, if it doesnt exist will make it
  fs.writeFile('./config.json', JSON.stringify(keyObj, null, 4), (ferr) => {
    if (ferr) console.error(`Error saving to config.json: ${ferr.message}`);
  });
}
 
 server.get('/', (req, res) => {
   // Return a response that documents the other routes/operations available
   res.send(`
   <html>
     <header><title>Secret Gists!</title></header>
     <body>
       <h1>Secret Gists!</h1>
       <div>This is an educational implementation.  Do not use for truly valuable information</div>
       <h2>Supported operations:</h2>
       <ul>
         <li><i><a href="/keyPairGen">Show Keypair</a></i>: generate a keypair from your secret key.  Share your public key for other users of this app to leave encrypted gists that only you can decode with your secret key.</li>
         <li><i><a href="/gists">GET /gists</a></i>: retrieve a list of gists for the authorized user (including private gists)</li>
         <li><i><a href="/key">GET /key</a></i>: return the secret key used for encryption of secret gists</li>
       </ul>
       <h3>Set your secret key to a specific key</h3>
       <form action="/setkey:keyString" method="get">
         Key String: <input type="text" name="keyString"><br>
         <input type="submit" value="Submit">
       </form>
       <h3>Create an *unencrypted* gist</h3>
       <form action="/create" method="post">
         Name: <input type="text" name="name"><br>
         Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
         <input type="submit" value="Submit">
       </form>
       <h3>Create an *encrypted* gist for yourself</h3>
       <form action="/createsecret" method="post">
         Name: <input type="text" name="name"><br>
         Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
         <input type="submit" value="Submit">
       </form>
       <h3>Retrieve an *encrypted* gist you posted for yourself</h3>
       <form action="/fetchmessagefromself:id" method="get">
         Gist ID: <input type="text" name="id"><br>
         <input type="submit" value="Submit">
       </form>
       <h3>Create an *encrypted* gist for a friend to decode</h3>
       <form action="/postmessageforfriend" method="post">
         Name: <input type="text" name="name"><br>
         Friend's Public Key String: <input type="text" name="publicKeyString"><br>
         Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
         <input type="submit" value="Submit">
       </form>
       <h3>Retrieve an *encrypted* gist a friend has posted</h3>
       <form action="/fetchmessagefromfriend:messageString" method="get">
         String From Friend: <input type="text" name="messageString"><br>
         <input type="submit" value="Submit">
       </form>
     </body>
   </html>
 `);
});
 
 server.get('/keyPairGen', (req, res) => {
  const keypair = nacl.box.keyPair.fromSecretKey(secretKey);
   res.send(`
   <html>
   <header><title>Keypair</title></header>
   <body>
     <h1>Keypair</h1>
     <div>Share your public key with anyone you want to be able to leave you secret messages.</div>
     <div>Keep your secret key safe.  You will need it to decode messages.  Protect it like a passphrase!</div>
     <br/>
     <div>Public Key: ${nacl.util.encodeBase64(keypair.publicKey)}</div>
     <div>Secret Key: ${nacl.util.encodeBase64(keypair.secretKey)}</div>
     <br/>
     <div><a href="/key">View Secret Key</a></div>
   </body>
   `);
 });

 server.get('/gists', (req, res) => {
  // Retrieve a list of all gists for the currently authed user
  github.gists.getForUser({ username })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
});
 
 server.get('/key', (req, res) => {
   // TODO: Display the secret key used for encryption of secret gists
  if (secretKey) {
    res.send(`
    <html>
      <header><title>Your Secret Key</title></header>
      <body>
        <h1>Secret Key</h1>
        <p>The Secret Key Is: ${secretKey}</p>
      </body>
    `);
  } else {
    res.send(`
    <html>
      <header></header>
      <body>
        <h1>No Key Yet</h1>
      </body>
    `);
  }
 });
 
 server.get('/setkey:keyString', (req, res) => {
   // TODO: Set the key to one specified by the user or display an error if invalid
   const keyString = req.query.keyString;
   try {
     // TODO:
    if (nacl.util.decodeUTF8(keyString).length === 32) {
      secretKey = nacl.util.decodeUTF8(keyString);
      const keyObj = { secretKey: nacl.util.encodeBase64(secretKey) };

      // Writes to config.json, if it doesnt exist will make it
      fs.writeFile('./config.json', JSON.stringify(keyObj, null, 4), (ferr) => {
        if (ferr) console.error(`Error saving to config.json: ${ferr.message}`);
      });
      res.send(`
      <html>
        <header><title>New Key Set</title></header>
        <body>
          <h1>Secret Key</h1>
          <p>The new Secret Key Is: ${secretKey}</p>
          <br/>
          <div>You can now <a href="/key">view</a> your Secret Key</div>
        </body>
      `);
    } else {
      res.send(`
      <html>
        <header><title>Invalid Key Size</title></header>
        <body>
          <h1>Invalid Secret Key Size</h1>
          <p>The Secret Key is still: ${secretKey}</p>
          <br/>
        </body>
      `);
    }
   } catch (err) {
     // failed
     res.send('Failed to set key.  Key string appears invalid.');
   }
  });
 
 server.get('/fetchmessagefromself:id', (req, res) => {
   // TODO:  Retrieve and decrypt the secret gist corresponding to the given ID
  const id = req.query.id;

  github.gists.get({ id })
    .then((response) => {
      const gist = response.data;
      const filename = Object.keys(gist.files)[0];

      const blob = gist.files[filename].content;

      if (blob) {
        let [nonce, cipher] = blob.split(' ');

        nonce = nacl.util.decodeBase64(nonce);
        cipher = nacl.util.decodeBase64(cipher);

        const plaintext = nacl.secretbox.open(cipher, nonce, secretKey);

        res.send(nacl.util.encodeUTF8(plaintext));
      } else res.json({ gist: response.data });
    })
    .catch((err) => {
      res.json({ err });
    });
 });
 
 server.post('/create', urlencodedParser, (req, res) => {
   // Create a private gist with name and content given in post request
   const { name, content } = req.body;
   const files = { [name]: { content } };
   github.gists.create({ files, public: false })
     .then((response) => {
       res.json(response.data);
     })
     .catch((err) => {
       res.json(err);
     });
 });

 server.post('/createsecret', urlencodedParser, (req, res) => {
   // TODO:  Create a private and encrypted gist with given name/content
   // NOTE - we're only encrypting the content, not the filename
  const { name, content } = req.body;

  const nonce = nacl.randomBytes(24);

  const cipher = nacl.secretbox(nacl.util.decodeUTF8(content), nonce, secretKey);

  const blob = `${nacl.util.encodeBase64(nonce)} ${nacl.util.encodeBase64(cipher)}`;

  const files = { [name]: { content: blob } };
  github.gists.create({ files, public: false })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
 });
 
 server.post('/postmessageforfriend', urlencodedParser, (req, res) => {
   // TODO:  Create a private and encrypted gist with given name/content
   // using someone else's public key that can be accessed and
   // viewed only by the person with the matching private key
   // NOTE - we're only encrypting the content, not the filename
  const { name, publicKeyString, content } = req.body;

  const nonce = nacl.randomBytes(24);

  const cipher = nacl.box(nacl.util.decodeUTF8(content), nonce, nacl.util.decodeBase64(publicKeyString), secretKey);

  const blob = `${nacl.util.encodeBase64(nonce)} ${nacl.util.encodeBase64(cipher)}`;

  const files = { [name]: { content: blob } };
  github.gists.create({ files, public: false })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
 });
 
 server.get('/fetchmessagefromfriend:messageString', urlencodedParser, (req, res) => {
   // TODO:  Retrieve and decrypt the secret gist corresponding to the given ID
  const messageString = req.query.messageString;
  console.log(messageString);
  const [pk, id] = messageString.split(' ');

  github.gists.get({ id })
    .then((response) => {
      const gist = response.data;
      console.log(gist);
      const filename = Object.keys(gist.files)[0];

      const blob = gist.files[filename].content;
      if (blob) {
        let [nonce, cipher] = blob.split(' ');

        nonce = nacl.util.decodeBase64(nonce);
        cipher = nacl.util.decodeBase64(cipher);

        const plaintext = nacl.box.open(cipher, nonce, nacl.util.decodeBase64(pk), secretKey);

        res.send(nacl.util.encodeUTF8(plaintext));
      } else res.json({ gist: response.data });
    })
    .catch((err) => {
      res.json({ err });
    });
 });
 
 /* OPTIONAL - if you want to extend functionality */