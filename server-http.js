'use strict';

const express = require('express');
const get_app_server = require('./app.js');
const database = require('./database.js');

const PORT = process.env.PORT || 3000;

(async () => {
	await database.database_init();

	const wrapper = express();
	wrapper.set('trust proxy', true);

	wrapper.use((req, res, next) => {
		if (req.path !== '/health') {
			req.connection.proxySecure = true;
		}
		next();
	});

	const app = await get_app_server();
	wrapper.use(app);

	wrapper.listen(PORT, '0.0.0.0', () => {
		console.log(`[INFO] Server listening on port ${PORT}`);
	});
})();
