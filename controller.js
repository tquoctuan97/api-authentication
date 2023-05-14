import config from './config.js'
import { signToken, verifyToken } from './utils/jwt.js'
import fs from 'fs'
import { STATUS, tokenType } from './constants.js'

const getDatabase = () => {
  const rawDB = fs.readFileSync('./database.json')
  const database = JSON.parse(rawDB)
  return database
}

const writeDatabase = (data) => {
  const databaseJSON = JSON.stringify(data)
  fs.writeFileSync('./database.json', databaseJSON)
}

export const loginController = async (req) => {
  const { username, password } = req.body

  const database = getDatabase()
  const isAccountExist = database.users.some(
    (user) => user.username === username && user.password === password
  )

  if(!isAccountExist) {
    return {
      status: STATUS.UNAUTHORIZED,
      response: {
        message: 'username hoặc password không đúng!'
      }
    }
  }

  const accessToken$ = signToken(
    {
      username,
      tokenType: tokenType.accessToken
    },
    config.jwt_expire_access_token
  )
  const refreshToken$ = signToken(
    {
      username,
      tokenType: tokenType.refreshToken
    },
    config.jwt_expire_refresh_token
  )

  const [access_token, refresh_token] = await Promise.all([
    accessToken$,
    refreshToken$
  ])

  database.refresh_tokens.push({
    username,
    token: refresh_token
  })

  writeDatabase(database)

  return {
    status: STATUS.OK,
    response: {
      message: 'Đăng nhập thành công',
      data: {
        access_token,
        refresh_token
      }
    }
  }
}

export const logoutController = async (req) => {
  const database = getDatabase()

  const newRefreshTokenList = database.refresh_tokens.filter(
    (refreshTokenObject) => refreshTokenObject.username !== req.username
  )

  database.refresh_tokens = newRefreshTokenList;

  writeDatabase(database)

  return {
    status: STATUS.OK,
    response: {
      message: 'Đăng xuất thành công',
    }
  }
}

export const refreshTokenController = async (req) => {
  const { refresh_token } = req.body
  try {
    const decodedRefreshToken = await verifyToken(
      refresh_token,
      tokenType.refreshToken
    )
    const { username } = decodedRefreshToken

    const database = getDatabase()
    const isAccountExist = database.users.some(
      (user) => user.username === username
    )
    const isRefreshTokenExist = database.refresh_tokens.some(
      (refreshTokenObject) => refreshTokenObject.token === refresh_token
    )

    if(!isAccountExist || !isRefreshTokenExist) {
      return {
        status: STATUS.NOT_FOUND,
        response: { message: 'Refresh Token không tồn tại' }
      }
    }

    // Delete old refresh token
    const indexToRemove = database.refresh_tokens.findIndex(
      (refreshTokenObject) => refreshTokenObject.token === refresh_token
    )

    database.refresh_tokens.splice(indexToRemove, 1);


    // Generate new access token and refresh token
    
    const accessToken$ = signToken(
      {
        username,
        tokenType: tokenType.accessToken
      },
      config.jwt_expire_access_token
    )

    const refreshToken$ = signToken(
      {
        username,
        tokenType: tokenType.refreshToken
      },
      config.jwt_expire_refresh_token
    )
  
    const [newAccessToken, newRefreshToken] = await Promise.all([
      accessToken$,
      refreshToken$
    ])

    database.refresh_tokens.push({
      username,
      token: newRefreshToken
    })

    writeDatabase(database)

    return {
      status: STATUS.OK,
      response: {
        message: 'Refresh Token thành công',
        data: { access_token: newAccessToken, refresh_token: newRefreshToken}
      }
    }
   
  } catch (error) {
    return { ...error, response: error.error }
  }
}

export const getProfileController = async (req) => {
  const database = getDatabase()
  const account = database.users.find((user) => user.username === req.username)

  if(!account) {
    return {
      status: STATUS.NOT_FOUND,
      response: { message: 'Không tồn tại user' }
    }
  }

  return {
    status: STATUS.OK,
    response: { message: 'Lấy thông tin profile thành công', data: account }
  }
}

export const getProductsController = async (req) => {
  const database = getDatabase()

  return {
    status: STATUS.OK,
    response: {
      message: 'Lấy danh sách sản phẩm thành công',
      data: database.products
    }
  }
}
