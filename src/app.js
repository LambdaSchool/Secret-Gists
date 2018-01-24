// import { urlencoded } from '../../../../AppData/Local/Microsoft/TypeScript/2.6/node_modules/@types/express';

const bodyParser = require('body-parser');
const express = require('express');
const GitHubApi = require('github');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');
const dotenv = require('dotenv').config();
const morgan = require('morgan');

const username = '47analogy'; // TODO: your GitHub username here
const github = new GitHubApi({ debug: true });
const server = express();

const urlencodedParser = server.use(bodyParser.urlencoded({ extended: false }));
server.use(bodyParser.json());
server.use(morgan('dev'));

// Generate an access token: https://github.com/settings/tokens
// Set it to be able to create gists

github.authenticate({
  type: 'oauth',
  token: process.env.GITHUB_TOKEN
});
// Set up the encryption - use process.env.SECRET_KEY if it exists
// TODO either use or generate a new 32 byte key
const key = process.env.SECRET_KEY
  ? nacl.util.decodeBase64(process.env.SECRET_KEY)
  : nacl.randomBytes(32);

/*
const key; //check to make sure key does not have to be initialized

if (process.env.SECRET_KEY) {
  key = nacl.util.decodeBase64(process.env.SECRET_KEY)
} else {
  key = nacl.randomBytes(32);
}
*/


server.get('/', (req, res) => {
  // *TODO Return a response that documents the other routes/operations available
  res.send('About to Get Data (document routes!)');
});

server.get('/gists', (req, res) => {
  // *TODO Retrieve a list of all gists for the currently authed user
  github.gists
    .getForUser({ username })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
});

server.get('/key', (req, res) => {
  // TODO Return the secret key used for encryption of secret gists
  res.send(nacl.util.encodeBase64(key));
});

server.get('/secretgist/:id', (req, res) => {
  // TODO Retrieve and decrypt the secret gist corresponding to the given ID
});

server.post('/create', urlencodedParser, (req, res) => {
  // TODO Create a private gist with name and content given in post request
  if (!req.body.name || !req.body.content) {
    res.json({ success: false, msg: 'Needs a name and content' });
  } else {
    const newGist = ({
      name: req.body.name,
      content: req.body.content
    });
    // create the gist
    github.gists.create({ newGist, public: false })
      .then((response) => {
        res.json(response.data);
      })
      .catch((err) => {
        res.json(err);
      });
  }
});

server.post('/createsecret', (req, res) => {
  // TODO Create a private and encrypted gist with given name/content
  // NOTE - we're only encrypting the content, not the filename
  // To save, we need to keep both encrypted content and nonce
});

/* OPTIONAL - if you want to extend functionality */
server.post('/login', (req, res) => {
  // TODO log in to GitHub, return success/failure response
  // This will replace hardcoded username from above
  // const { username, oauth_token } = req.body;
  res.json({ success: false });
});

/*
Still want to write code? Some possibilities:
-Pretty templates! More forms!
-Better management of gist IDs, use/display other gist fields
-Support editing/deleting existing gists
-Switch from symmetric to asymmetric crypto
-Exchange keys, encrypt messages for each other, share them
-Let the user pass in their private key via POST
*/

server.listen(3001);
console.log('listening on 3001');  // REMOVE
