module.exports = {
  port: 3000,
  db: {
    name: 'login',
    user: 'root',
    password: 'abc123_'
  },
  role: {
    admin: 2,
    normal: 1
  },
  token: {
    secret: 'react',
    expired: '1d'
  },
  errCode: {
    1000: 'USER_NOT_EXISTED',
    1001: 'WRONG_PASSWORD',
    1002: 'PERMISSION_DENIED'
  }
}