import { Router } from 'express'
import {
  getProfileController,
  getProductsController,
  loginController,
  logoutController,
  refreshTokenController
} from './controller.js'
import { verifyToken } from './utils/jwt.js';

const router = Router()

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(STATUS.UNAUTHORIZED).json({ message: 'Missing access token' });
    return;
  }
  
  // Verify access token and get user ID
  try {
    const decoded = await verifyToken(token)
    req.username = decoded.username;
    next();
  } catch(err) {
    res.status(err.status).json(err.error);
    return;
  }
}

router.post('/login', async (req, res) => {
  const resData = await loginController(req)
  res.status(resData.status).send(resData.response)
})

router.post('/refresh-token', async (req, res) => {
  const resData = await refreshTokenController(req)
  res.status(resData.status).send(resData.response)
})

router.post('/logout', authenticateToken, async (req, res) => {
  const resData = await logoutController(req)
  res.status(resData.status).send(resData.response)
})

router.get('/profile', authenticateToken, async (req, res) => {
  const resData = await getProfileController(req)
  res.status(resData.status).send(resData.response)
})

router.get('/products', authenticateToken, async (req, res) => {
  const resData = await getProductsController(req)
  res.status(resData.status).send(resData.response)
})

export default router
