'use strict'

const express       = require('express')
const model         = require('../models')
const jsonwebtoken  = require('jsonwebtoken')
const jwt           = require('express-jwt')
const blacklist = require('express-jwt-blacklist');
const config        = require('../config')
const getErrorMessage  = require('../utils/message-handle')
const md5           = require('md5');

const router        = express.Router()
const User          = model.users
const app = express();


router.use(jwt({
    secret: config.token.secret,
    credentialsRequired: false,
    getToken: function fromHeaderOrQuerystring (req) {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            let secretKey = app.get('secretKey');
            let tokenInMemory = app.get(secretKey);

            let token = req.headers.authorization.split(' ')[1];
            if(tokenInMemory === token){
                return token;
            }
        } else if (req.query && req.query.token) {
            return req.query.token;
        }
        return null;
    }
}).unless({path:['/api/user/login']}));

// router.use(jwt({
//
// }).unless({path:['/api/user/login']}))

// app.use((req, res, next) => {
//     let token = req.headers.authorization.split(' ')[1];
//
// });

// Find all users
router.get('/', (req, res)=>{
  if(req.user.role === config.role.admin) {
    User.findAll({
      attributes: ['username', 'id']
    }).then((result) => {
      res.send(result)
    })
  } else {
    res.json(getErrorMessage(1002))
  }
})


router.post('/register', (req, res) => {
  const {username, password, email} = req.body
  User.findOne({
    where: {
      username: username
    }
  }).then((user) => {
    if(!user) {
      User
        .build({
          username: username,
          password: password,
          email: email
        })
        .save()
        .then(() => {
          const token = jsonwebtoken.sign({
            username: username,
            role: config.role.normal, // default is normal
          }, config.token.secret, { // get secret from config
            expiresIn: '1d' // expires in 1 day
          })

          res.json({
            username: username,
            email: email,
            token: token
          })
        }).catch((err) => {
          throw err
      })
    } else {
      res.send('User has already existed!')
    }
  })
})

router.post('/login', (req, res, next) => {
  const {username, password} = req.body
  User
    .findOne({
      where: {
        username: username,
        password: password
      }
    })
    .then((user) => {
      if(user) {
        const roleId = user.get('roleId')
          //setSecretKey(user.get('username'), user.get('id'));
        const token = jsonwebtoken.sign({
          username: username,
          role: roleId,
        }, config.token.secret, { // get secret from config
          expiresIn: config.token.expired // expires in 1 day
        })
        res.json({
          username: username,
          token: token,
          email: user.get('email')
        })
          saveToken(username, token);
      } else {
        res.json(getErrorMessage(1001))
      }
    })
})

function saveToken(username, token){
    let currentTimeStamp = new Date().getTime();
    let salt = md5([username,currentTimeStamp].join('_'));
    app.set('secretKey',salt);
    app.set(salt,token);
}

function setSecretKey(username, userId){
    let secretKey = config.token.secret;
    let currentTimeStamp = new Date().getTime();
    let salt = [secretKey,username, userId,currentTimeStamp].join('_');
    let value = md5(salt);
    let key = md5([].join.call(username,userId));
    app.set('secretKey',key);
    app.set(key,value);
}

function getSecretKey(){
    let secretKey = app.get('secretKey');
    let value = app.get(secretKey);
    if(!value){
        value = config.token.secret;
    }
    return value;
}

router.get('/logout', (req, res) => {
    blacklist.revoke(req.user);
    res.sendStatus(200);
})


// normal user action
router.post('/action1', (req, res) => { // normal will be ok
  res.json({
    content: 'ok, action1'
  })
})

// admin user action
router.post('/action2', (req, res, next) => { // only for admin
  if(req.user.role === config.role.admin) {
    res.json({
      content: 'ok, action2'
    })
  } else {
    res.json(getErrorMessage(1002))
  }
})

module.exports = router
