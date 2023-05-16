import type { RequestEvent } from './$types';
import jwt from 'jsonwebtoken';
import { SECRET_ACCESS, SECRET_COMM, SECRET_REFRESH } from '$env/static/private';

// cannot receive cookies if on Vercel!
// embed cookies in header instead
export const POST = async ({ cookies, request }: RequestEvent) => {
	const commHeader = request.headers.get('ACCESS_CONTROL_COMM_TOKEN');

	if (!commHeader)
		return new Response(
			JSON.stringify({ error: true, success: false, message: 'Invalid Request', data: undefined }),
			{ status: 401 }
		);

	try {
		const claims = jwt.verify(commHeader, SECRET_COMM) as { [key: string]: any };
		if (!claims)
			return new Response(
				JSON.stringify({ error: true, success: false, message: 'Unauthorized', data: undefined }),
				{ status: 401 }
			);

		if (claims) {
			const newAccessToken = jwt.sign({ authedUser: claims.authedUser }, SECRET_ACCESS, {
				expiresIn: '10m'
			});
			cookies.set('authToken', newAccessToken, {
				httpOnly: true,
				maxAge: 60 * 60 * 24,
				sameSite: 'strict'
			});

			const newRefreshToken = jwt.sign({ authedUser: claims.authedUser }, SECRET_REFRESH, {
				expiresIn: '120d'
			});
			cookies.set('refreshToken', newRefreshToken, {
				httpOnly: true,
				maxAge: 60 * 60 * 24 * 120,
				sameSite: 'strict'
			});

			return new Response(
				JSON.stringify({ error: false, success: true, message: 'Success', data: undefined }),
				{ status: 200 }
			);
		}
	} catch (err) {
		if (error.name === 'TokenExpiredError') {
			return new Response(
				JSON.stringify({ error: true, success: false, message: 'Token Expired', data: undefined }),
				{ status: 401 }
			);
		}
		if (error.name === 'JsonWebTokenError') {
			return new Response(
				JSON.stringify({ error: true, success: false, message: 'Invalid Token', data: undefined }),
				{ status: 401 }
			);
		}
		if (error.name === 'NotBeforeError') {
			return new Response(
				JSON.stringify({
					error: true,
					success: false,
					message: 'Token Not Active',
					data: undefined
				}),
				{ status: 401 }
			);
		}
	}

	return new Response(
		JSON.stringify({ error: true, success: false, message: 'Invalid Request', data: undefined }),
		{ status: 500 }
	);
};
