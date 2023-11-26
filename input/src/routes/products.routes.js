import { Router } from 'express';
const router = Router();

import { verifyToken } from '../middlewares';
import { getProducts, getProductById } from '../controllers/products.controller';

/**
 * 
 * /products/:
 *   get:
 *     summary: Obtener la lista de todos los productos
 *     description: Endpoint para obtener la lista de todos los productos.
 *     responses:
 *       '200':
 *         description: Respuesta exitosa
 *         content:
 *           application/json:
 *             example:
 *               - success: booleano
 *                 response: un arreglo con todos los productos o error message
 */

router.get('/', verifyToken, getProducts);

/**
 * 
 * /products/:productId:
 *   get:
 *     summary: Obtener un producto de la lista de todos los productos
 *     description: Endpoint para obtener un producto de la lista de todos los productos.
 *     responses:
 *       '200':
 *         description: Respuesta exitosa
 *         content:
 *           application/json:
 *             example:
 *               - success: booleano
 *                 response: un objeto con un producto en especifico o error message
 */

router.get('/:productId', verifyToken, getProductById);

export default router;