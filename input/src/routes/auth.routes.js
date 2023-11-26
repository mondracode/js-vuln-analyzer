import { Router } from 'express';
import { signin, signup } from '../controllers/auth.controller';
import { checkDuplicateEmail, checkDuplicateUsername } from '../middlewares';

const router = Router();

/**
 * 
 * /auth/signin:
 *   post:
 *     summary: Logearse en la aplicacion
 *     description: Endpoint para logearse en la aplicacion.
 *     responses:
 *       '200':
 *         description: Respuesta exitosa
 *         content:
 *           application/json:
 *             example:
 *               - success: booleano
 *                 response: tokenid o error message
 */

router.post('/signin', signin);

/**
 * 
 * /auth/signup:
 *   post:
 *     summary: Registrar nuevos usuarios
 *     description: Endpoint para registrar nuevos usuarios en la aplicacion.
 *     responses:
 *       '200':
 *         description: Respuesta exitosa
 *         content:
 *           application/json:
 *             example:
 *               - success: booleano
 *                 response: tokenid o error message
 */

router.post('/signup', [checkDuplicateUsername, checkDuplicateEmail], signup);

export default router;