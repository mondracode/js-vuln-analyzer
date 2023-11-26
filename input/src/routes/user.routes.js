import { Router } from 'express';
const router = Router();

import { verifyToken } from '../middlewares';
import { getUserByToken, getUsers } from '../controllers/user.controller';

/**
 * 
 * users/:
 *   get:
 *     summary: retorna la lista de usuarios registrados en la base de datos
 *     description: Endpoint para obtener la lista de usuarios registrados en la base de datos.
 *     responses:
 *       '200':
 *         description: Respuesta exitosa
 *         content:
 *           application/json:
 *             example:
 *               - success: booleano
 *                 response: un arreglo con la lista de todos los usuarios de la aplicacion o error message
 */

router.get('/', verifyToken, getUsers);

/**
 * 
 * /users/byToken:
 *   get:
 *     summary: Obtener el usuario correspondiente al jwt
 *     description: Endpoint para obtener el usuario correspondiente al jwt.
 *     responses:
 *       '200':
 *         description: Respuesta exitosa
 *         content:
 *           application/json:
 *             example:
 *               - success: booleano
 *                 response: un usuario especifico dado un tokenId o error message
 */

router.get('/byToken', verifyToken, getUserByToken);

export default router;