// ============================================================
// 配置说明
// 推荐方式（安全）：在 Worker 的 Settings → Variables 中配置环境变量，
// 敏感项（SECRET_KEY / TELEGRAM_BOT_TOKEN）用 "Secret" 类型：
//   SECRET_KEY          Web 后台访问密码
//   TELEGRAM_BOT_TOKEN  Telegram Bot Token
//   CHAT_ID             允许访问的聊天 ID，多个用英文逗号分隔
//   BUCKET_NAME         R2 存储桶绑定变量名
//   BASE_URL            R2 访问域名（不带末尾斜杠）
//   WEBHOOK_SECRET      （推荐）webhook 防伪随机串，任意 32+ 位随机字符
// 以下常量仅作为未配置环境变量时的兜底（兼容旧部署，建议留空并全部用环境变量）
// ============================================================
const FALLBACK = {
	SECRET_KEY: "***你的Web后台访问密码***",
	TELEGRAM_BOT_TOKEN: "***你的Telegram Bot Token***",
	CHAT_ID: ["***允许访问的聊天ID***"],
	BUCKET_NAME: "***你的R2存储桶绑定变量名***",
	BASE_URL: "https://***你的访问域名***"
};

const UPLOAD_MAX_BYTES = 25 * 1024 * 1024; // Web 上传大小上限（超限返回 413）
const TG_MAX_BYTES = 20 * 1024 * 1024;     // Telegram Bot API 可下载文件上限
const COOKIE_NAME = 'auth';
const COOKIE_MAX_AGE = 604800; // 7 天

function getConfig(env) {
	let chatIds = FALLBACK.CHAT_ID;
	if (env.CHAT_ID !== undefined && env.CHAT_ID !== null && String(env.CHAT_ID).trim() !== '') {
		chatIds = String(env.CHAT_ID).split(',').map(s => s.trim()).filter(Boolean);
	}
	return {
		secretKey: env.SECRET_KEY || FALLBACK.SECRET_KEY,
		botToken: env.TELEGRAM_BOT_TOKEN || FALLBACK.TELEGRAM_BOT_TOKEN,
		chatIds,
		bucketName: env.BUCKET_NAME || FALLBACK.BUCKET_NAME,
		baseUrl: String(env.BASE_URL || FALLBACK.BASE_URL).replace(/\/+$/, ''),
		webhookSecret: env.WEBHOOK_SECRET || ''
	};
}

function telegramApiUrl(cfg) {
	return `https://api.telegram.org/bot${cfg.botToken}`;
}

// 规范化用户提供的文件夹路径：
//   '' / '/' / '  '            → ''（根目录）
//   'blog' / '/blog/' / 'a//b' → 'blog' / 'a/b'
//   含 .. 、非法字符（仅允许中文/字母/数字/下划线/短横线）→ null
function sanitizeFolderPath(input) {
	if (typeof input !== 'string') return null;
	const trimmed = input.trim().replace(/^\/+|\/+$/g, '');
	if (trimmed === '') return '';
	if (trimmed.length > 200) return null;
	const segments = trimmed.split('/').filter(s => s !== '');
	if (segments.length === 0) return '';
	for (const seg of segments) {
		if (seg === '.' || seg === '..') return null;
		if (!/^[\w\u4e00-\u9fa5-]+$/.test(seg)) return null;
	}
	return segments.join('/');
}

function escapeHtml(s) {
	return String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

function jsonOk(data) {
	return new Response(JSON.stringify(Object.assign({success: true}, data)), {
		headers: {'Content-Type': 'application/json'}
	});
}

function jsonError(status, code, message) {
	return new Response(JSON.stringify({success: false, code, message}), {
		status,
		headers: {'Content-Type': 'application/json'}
	});
}

// ============================ 回收站 ============================
// 软删除：把对象 copy 到 __trash__/<原key> 再删原件；恢复反向操作。
// 前缀选 __trash__（下划线开头），与老项目的日期前缀 key 天然不冲突，切换无损。

const TRASH_PREFIX = '__trash__/';
const TRASH_RETENTION_DAYS = 30; // scheduled Cron 清理超过该天数的回收站对象（需自行配置 Cron trigger）

function isTrashKey(key) {
	return typeof key === 'string' && key.startsWith(TRASH_PREFIX);
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;
		const cfg = getConfig(env);
		const bucket = env[cfg.bucketName];

		try {
			// Telegram webhook（配置了 WEBHOOK_SECRET 时强制校验请求头）
			if (path === '/webhook' && request.method === 'POST') {
				return handleTelegramWebhook(request, env, cfg);
			}

			// 退出登录
			if (path === '/logout') {
				return handleLogout(request, env);
			}

			// 登录
			if (path === '/login' && request.method === 'POST') {
				return handleLogin(request, env, cfg);
			}
			if (path === '/' || path === '/index.html') {
				if (await isAuthenticated(request, env, cfg)) {
					return new Response(null, {status: 302, headers: {'Location': '/upload'}});
				}
				return serveLoginPage(url.searchParams.get('next') || '');
			}

			// 页面（未登录一律 302 到登录页，不再返回页面壳）
			if (path === '/upload') {
				if (await isAuthenticated(request, env, cfg)) return serveUploadPage();
				return redirectToLogin(url);
			}
			if (path === '/gallery') {
				if (await isAuthenticated(request, env, cfg)) return serveGalleryPage();
				return redirectToLogin(url);
			}

			// Web API（未登录统一返回 401 JSON；状态变更接口做同源校验）
			if (path.startsWith('/api/')) {
				if (!(await isAuthenticated(request, env, cfg))) {
					return jsonError(401, 'UNAUTHORIZED', '未登录或登录已过期');
				}
				const origin = request.headers.get('Origin');
				if (origin && origin !== url.origin) {
					return jsonError(403, 'FORBIDDEN_ORIGIN', '跨站请求被拒绝');
				}
				switch (path) {
					case '/api/upload':
						return handleWebUpload(request, env, bucket, cfg);
					case '/api/list':
						return handleListFiles(request, bucket, cfg.baseUrl);
					case '/api/delete':
						return handleDeleteFiles(request, env, bucket);
					case '/api/create-folder':
						return handleCreateFolder(request, bucket);
					case '/api/delete-folder':
						return handleDeleteFolder(request, env, bucket);
					case '/api/rename':
						return handleRename(request, env, bucket);
					case '/api/stats':
						return handleStats(request, env, bucket);
					case '/api/trash':
						return handleTrashList(request, env, bucket);
					case '/api/trash/restore':
						return handleTrashRestore(request, env, bucket);
					case '/api/trash/purge':
						return handleTrashPurge(request, env, bucket);
					default:
						return jsonError(404, 'NOT_FOUND', '接口不存在');
				}
			}

			// Telegram set webhook（需登录后访问，防止被陌生人滥用重置 webhook）
			if (path === '/setWebhook') {
				if (!(await isAuthenticated(request, env, cfg))) {
					return new Response('请先登录 Web 后台后再访问 /setWebhook', {status: 401});
				}
				const webhookUrl = `${url.protocol}//${url.host}/webhook`;
				const webhookResponse = await setWebhook(webhookUrl, cfg);
				if (webhookResponse.ok) {
					const hint = cfg.webhookSecret ? '' : '（提示：未配置 WEBHOOK_SECRET 环境变量，webhook 防伪造校验未启用，建议配置）';
					return new Response(`Webhook set successfully to ${webhookUrl}${hint}`);
				}
				return new Response(`设置失败: ${webhookResponse.description || 'unknown'}`, {status: 500});
			}

			// 代理访问 R2 中存储的图片文件（图床直链）
			const reserved = ['/webhook', '/setWebhook', '/login', '/logout', '/upload', '/gallery', '/index.html', '/favicon.ico'];
			if (path !== '/' && !path.startsWith('/api/') && !reserved.includes(path)) {
				const key = decodeKey(path.substring(1));
				if (!key) return new Response('Not Found', {status: 404});
				const object = await bucket.get(key);
				if (object !== null) {
					const headers = new Headers();
					object.writeHttpMetadata(headers);
					headers.set('Cache-Control', 'public, max-age=31536000');
					return new Response(object.body, {headers: headers});
				}
				return new Response('Not Found', {status: 404});
			}

			return new Response('Not found', {status: 404});
		} catch (err) {
			console.error(err);
			return new Response('Server error', {status: 500});
		}
	},

	// 可选 Cron：配置了 Cron Trigger（如每天 0 0 * * *）后自动清空超过保留期的回收站对象。
	// 未配置 trigger 时永远不会被调用，不影响 Dashboard 粘贴部署。
	async scheduled(event, env, ctx) {
		const cfg = getConfig(env);
		const bucket = env[cfg.bucketName];
		if (!bucket) return;
		const cutoff = Date.now() - TRASH_RETENTION_DAYS * 86400000;
		const expired = [];
		let r2Cursor;
		do {
			const page = await bucket.list({prefix: TRASH_PREFIX, limit: 1000, cursor: r2Cursor});
			for (const object of page.objects) {
				if (object.uploaded && new Date(object.uploaded).getTime() < cutoff) {
					expired.push(object.key);
				}
			}
			r2Cursor = page.truncated ? page.cursor : undefined;
			if (expired.length >= 5000) break;
		} while (r2Cursor);

		for (let i = 0; i < expired.length; i += 1000) {
			await bucket.delete(expired.slice(i, i + 1000));
		}
		if (expired.length > 0) {
			await invalidateStatsCache(env);
			console.log(`Trash cleanup: removed ${expired.length} expired objects`);
		}
	}
};

// 解码并校验直链 key，畸形编码一律按 404 处理
function decodeKey(rawPath) {
	try {
		const key = decodeURIComponent(rawPath);
		if (!key || key.length > 1024 || key.includes('\x00')) return null;
		return key;
	} catch (e) {
		return null;
	}
}

function redirectToLogin(url) {
	const next = sanitizeNext(url.pathname + (url.search || ''));
	return new Response(null, {
		status: 302,
		headers: {'Location': '/?next=' + encodeURIComponent(next || '/upload')}
	});
}

// 只允许站内相对路径，防开放重定向
function sanitizeNext(next) {
	if (typeof next !== 'string') return '';
	if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\')) return '';
	return next;
}

async function handleLogout(request, env) {
	// 吊销服务端会话（KV 删除），同时清除浏览器 Cookie
	const token = parseCookies(request.headers.get('Cookie') || '')[COOKIE_NAME];
	if (token && env.INDEXES_KV) {
		try {
			await env.INDEXES_KV.delete(`sess:${token}`);
		} catch (e) { /* KV 不可用时仍清除本地 Cookie */ }
	}
	const headers = new Headers();
	headers.append('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
	headers.append('Location', '/');
	return new Response(null, {status: 302, headers});
}

// 统计缓存失效（上传/删除/重命名后调用，保证统计近实时）
async function invalidateStatsCache(env) {
	try {
		await env.INDEXES_KV.delete('stats:root:v1');
	} catch (e) { /* 缓存失效失败不影响主流程 */ }
}

// 文件名校验（比文件夹多允许点号：扩展名）
function sanitizeFileName(name) {
	if (typeof name !== 'string') return null;
	const trimmed = name.trim();
	if (trimmed === '' || trimmed.length > 200) return null;
	if (!/^[\w\u4e00-\u9fa5.-]+$/.test(trimmed)) return null;
	if (trimmed === '.' || trimmed === '..') return null;
	return trimmed;
}

async function setWebhook(webhookUrl, cfg) {
	const apiUrl = telegramApiUrl(cfg);
	try {
		const body = {url: webhookUrl};
		if (cfg.webhookSecret) {
			body.secret_token = cfg.webhookSecret;
		}
		const response = await fetch(`${apiUrl}/setWebhook`, {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify(body),
		});

		const result = await response.json();

		if (!result.ok) {
			console.error('Failed to set webhook:', result.description);
		}

		return result;
	} catch (error) {
		console.error('Error setting webhook:', error);
		return {ok: false, description: error.message};
	}
}

function detectImageType(uint8Array) {
	// Check for JPEG signature (FF D8 FF)
	if (uint8Array.length >= 3 &&
		uint8Array[0] === 0xFF &&
		uint8Array[1] === 0xD8 &&
		uint8Array[2] === 0xFF) {
		return {mime: 'image/jpeg', ext: 'jpg'};
	}

	// Check for PNG signature (89 50 4E 47 0D 0A 1A 0A)
	const pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
	if (uint8Array.length >= pngSignature.length) {
		const isPng = pngSignature.every(
			(byte, index) => uint8Array[index] === byte
		);
		if (isPng) return {mime: 'image/png', ext: 'png'};
	}

	// Check for GIF signature (GIF87a or GIF89a)
	if (uint8Array.length >= 6) {
		const gifHeader = String.fromCharCode(...uint8Array.slice(0, 6));
		if (gifHeader === 'GIF87a' || gifHeader === 'GIF89a') {
			return {mime: 'image/gif', ext: 'gif'};
		}
	}

	// Check for WebP signature (RIFF followed with "WEBP")
	if (uint8Array.length >= 12) {
		const riffHeader = String.fromCharCode(...uint8Array.slice(0, 4));
		const webpTag = String.fromCharCode(...uint8Array.slice(8, 12));
		if (riffHeader === 'RIFF' && webpTag === 'WEBP') {
			return {mime: 'image/webp', ext: 'webp'};
		}
	}

	// Check for BMP
	if (uint8Array.length >= 2) {
		const bmpHeader = String.fromCharCode(...uint8Array.slice(0, 2));
		if (bmpHeader === 'BM') {
			return {mime: 'image/bmp', ext: 'bmp'};
		}
	}

	return null;
}

async function handleTelegramWebhook(request, env, cfg) {
	const apiUrl = telegramApiUrl(cfg);
	try {
		// webhook 防伪造：配置了 WEBHOOK_SECRET 时校验 Telegram 回传的请求头
		if (cfg.webhookSecret) {
			const sig = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
			if (sig !== cfg.webhookSecret) {
				// 自愈（无损切换）：部署新代码并配置 SECRET 后、但还未重跑 /setWebhook 时，
				// Telegram 仍用旧密钥（或不带密钥）回调，这里自动重新注册一次 webhook。
				// KV 节流 1 小时，防止被恶意请求反复触发对 Telegram API 的调用。
				try {
					const throttleKey = 'webhook:heal:last';
					const last = parseInt(await env.INDEXES_KV.get(throttleKey)) || 0;
					if (Date.now() - last > 3600 * 1000) {
						await env.INDEXES_KV.put(throttleKey, String(Date.now()), {expirationTtl: 3700});
						const webhookUrl = new URL(request.url);
						webhookUrl.pathname = '/webhook';
						webhookUrl.search = '';
						await setWebhook(webhookUrl.toString(), cfg);
					}
				} catch (healError) {
					console.error('Webhook self-heal failed:', healError);
				}
				return new Response('Forbidden', {status: 403});
			}
		}

		const update = await request.json();

		if (!update.message) {
			return new Response('OK');
		}

		const chatId = update.message.chat.id;

		// Check if user is authorized
		if (!cfg.chatIds.includes(chatId.toString())) {
			return new Response('Unauthorized access', {status: 403});
		}

		// Get functions for path management
		async function getUserPath(chatId) {
			const path = await env.INDEXES_KV.get(chatId.toString());
			if (path === '/') {
				return '';
			}
			return path || ''; // Default to empty string (root path)
		}

		async function setUserPath(chatId, path) {
			await env.INDEXES_KV.put(chatId.toString(), path);
		}

		// Handle media uploads
		async function handleMediaUpload(chatId, fileId, isDocument = false) {
			try {
				await sendMessage(chatId, '收到文件，正在上传ing', apiUrl);

				const fileUrl = await getFileUrl(fileId, cfg.botToken);
				const userPath = await getUserPath(chatId);
				const uploadResult = await uploadImageToR2(fileUrl, env[cfg.bucketName], isDocument, userPath);

				if (uploadResult.ok) {
					// key 可能含中文/空格（如"图片/xxx.jpg"），TG 服务器抓取前必须 percent-encode
					const publicUrl = `${cfg.baseUrl}/${uploadResult.key.split('/').map(encodeURIComponent).join('/')}`;
					const caption = `✅ 图片上传成功！\n直链\n<code>${escapeHtml(publicUrl)}</code>\nMarkdown\n<code>![img](${escapeHtml(publicUrl)})</code>`;
					const sent = await sendPhoto(chatId, publicUrl, apiUrl, caption, {parse_mode: "HTML"});
					// sendPhoto 失败（TG 抓图失败/webp 不识别等）时降级为文本消息（带重试）
					if (!sent || !sent.ok) {
						const ok2 = await sendMessageReliable(chatId, `✅ 图片上传成功！\n直链：${publicUrl}\nMarkdown：![img](${publicUrl})`, apiUrl);
						if (!ok2) {
							// 兜底：让用户明确知道图已保存，只是回显失败
							await sendMessageReliable(chatId, `⚠️ 图片已成功保存到图床，但回显消息发送失败（TG 接口异常）。可到 Web 后台查看。`, apiUrl);
						}
					}
				} else {
					await sendMessage(chatId, uploadResult.message, apiUrl);
				}
			} catch (error) {
				console.error('处理文件失败:', error);
				await sendMessage(chatId, '文件处理失败，请稍后再试。', apiUrl);
			}
		}

		// Process text messages
		if (update.message.text) {
			const text = update.message.text.trim();

			// Handle /modify command
			if (text.startsWith('/modify')) {
				const parts = text.split(/\s+/);
				if (parts.length >= 2 && parts[1].trim()) {
					const normalized = sanitizeFolderPath(parts[1].trim());
					if (normalized === null) {
						await sendMessage(chatId, '路径格式无效：仅允许中文、字母、数字、下划线和短横线，不能包含 . .. 等片段', apiUrl);
					} else if (normalized === '') {
						await setUserPath(chatId, '');
						await sendMessage(chatId, '已恢复为根目录', apiUrl);
					} else {
						await setUserPath(chatId, normalized);
						await sendMessage(chatId, `修改路径为 ${normalized}`, apiUrl);
					}
				} else {
					await sendMessage(chatId, '请指定路径，例如：/modify blog', apiUrl);
				}
				return new Response('OK');
			}

			// Handle /status command
			if (text === '/status') {
				const currentPath = await getUserPath(chatId);
				const statusMessage = currentPath ? `当前路径: ${currentPath}` : '当前路径: / (默认)';
				await sendMessage(chatId, statusMessage, apiUrl);
				return new Response('OK');
			}

			// Default message for any other text
			let mes = `请发送一张图片！\n或者使用以下命令：\n/modify 修改上传图片的存储路径\n/status 查看当前上传图片的路径`;
			await sendMessage(chatId, mes, apiUrl);
			return new Response('OK');
		}

		// Handle document files
		if (update.message.document) {
			const doc = update.message.document;
			const fileName = doc.file_name || '';
			const fileExt = fileName.split('.').pop().toLowerCase();

			if (!['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].includes(fileExt)) {
				await sendMessage(chatId, '不支持的文件类型，请发送 JPG/PNG/GIF/WebP/BMP 格式文件', apiUrl);
				return new Response('OK');
			}

			await handleMediaUpload(chatId, doc.file_id, true);
			return new Response('OK');
		}

		// Handle photos
		if (update.message.photo) {
			const fileId = update.message.photo.slice(-1)[0].file_id;
			await handleMediaUpload(chatId, fileId);
			return new Response('OK');
		}

		return new Response('OK');
	} catch (err) {
		console.error(err);
		return new Response('Error processing request', {status: 500});
	}
}

// ============================ 认证 ============================
// M 档会话：登录成功签发随机 token，KV 存 sess:{token}（TTL 自动过期）。
// 支持：登出吊销、改密失效（会话内记录签发时的密码指纹）、服务端强制过期。

const SESSION_TTL = 604800; // 会话有效期：7 天（KV TTL 自动清理）

async function passwordFingerprint(secretKey) {
	return sha256Hex(secretKey + '::r2-gallery-pv-v1');
}

async function createSession(env, cfg) {
	const token = (crypto.randomUUID() + crypto.randomUUID()).replace(/-/g, '');
	await env.INDEXES_KV.put(
		`sess:${token}`,
		JSON.stringify({ exp: Date.now() + SESSION_TTL * 1000, pv: await passwordFingerprint(cfg.secretKey) }),
		{ expirationTtl: SESSION_TTL }
	);
	return token;
}

async function isAuthenticated(request, env, cfg) {
	const cookies = parseCookies(request.headers.get('Cookie') || '');
	const token = cookies[COOKIE_NAME];
	if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return false;
	let raw;
	try {
		raw = await env.INDEXES_KV.get(`sess:${token}`);
	} catch (e) {
		return false;
	}
	if (!raw) return false;
	try {
		const sess = JSON.parse(raw);
		if (!sess || typeof sess.exp !== 'number' || sess.exp < Date.now()) return false;
		// 改密后旧会话全部失效
		if (sess.pv !== await passwordFingerprint(cfg.secretKey)) return false;
		return true;
	} catch (e) {
		return false;
	}
}

async function handleLogin(request, env, cfg) {
	// 登录限速：按 IP 每小时窗口最多失败 5 次（KV 计数，粗粒度即可）
	const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
	const failKey = `loginfail:${ip}:${new Date().toISOString().slice(0, 13)}`;
	const failCount = parseInt(await env.INDEXES_KV.get(failKey)) || 0;
	if (failCount >= 5) {
		return serveLoginPage('失败次数过多，请一小时后再试', sanitizeNext(new URL(request.url).searchParams.get('next') || ''));
	}

	const formData = await request.formData();
	const inputKey = formData.get('key') || '';
	const next = sanitizeNext(formData.get('next') || '');

	const inputHash = await sha256Hex(String(inputKey));
	const expectedHash = await sha256Hex(cfg.secretKey);
	if (!timingSafeEqual(inputHash, expectedHash)) {
		// 记失败 + 轻微延迟抬高爆破成本
		await env.INDEXES_KV.put(failKey, String(failCount + 1), {expirationTtl: 3600});
		await new Promise(r => setTimeout(r, 800));
		return serveLoginPage('密钥错误，请重新输入', next);
	}

	const token = await createSession(env, cfg);
	const headers = new Headers();
	headers.append('Set-Cookie',
		`${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`);
	headers.append('Location', next || '/upload');
	return new Response(null, {status: 302, headers});
}

async function sha256Hex(text) {
	const data = new TextEncoder().encode(text);
	const digest = await crypto.subtle.digest('SHA-256', data);
	return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 常量时间字符串比较（长度不同同样完整遍历，避免长度泄露）
function timingSafeEqual(a, b) {
	const aBytes = new TextEncoder().encode(String(a));
	const bBytes = new TextEncoder().encode(String(b));
	let diff = aBytes.length ^ bBytes.length;
	const n = Math.min(aBytes.length, bBytes.length);
	for (let i = 0; i < n; i++) {
		diff |= aBytes[i] ^ bBytes[i];
	}
	return diff === 0;
}

function parseCookies(cookieString) {
	const cookies = {};
	cookieString.split(';').forEach(cookie => {
		const trimmed = cookie.trim();
		const idx = trimmed.indexOf('=');
		if (idx > 0) {
			cookies[trimmed.slice(0, idx)] = trimmed.slice(idx + 1);
		}
	});
	return cookies;
}

// Page Rendering Functions
function serveLoginPage(errorMessage = null, next = '') {
	const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>R2管理 - 登录</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
          background-color: #fbfbfd;
          color: #1d1d1f;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
        }

        .login-container {
          background-color: white;
          border-radius: 18px;
          box-shadow: 0 4px 24px rgba(0, 0, 0, 0.1);
          width: 90%;
          max-width: 420px;
          padding: 2.5rem;
          text-align: center;
        }

        h1 {
          font-weight: 600;
          font-size: 1.8rem;
          margin-bottom: 1.5rem;
        }

        .input-group {
          margin-bottom: 2rem;
        }

        input {
          width: 100%;
          padding: 0.8rem 1rem;
          border: 1px solid #d2d2d7;
          border-radius: 12px;
          font-size: 1rem;
          transition: border-color 0.3s;
        }

        input:focus {
          outline: none;
          border-color: #0071e3;
          box-shadow: 0 0 0 2px rgba(0, 113, 227, 0.2);
        }

        button {
          background-color: #0071e3;
          color: white;
          border: none;
          border-radius: 12px;
          padding: 0.8rem 2rem;
          font-size: 1rem;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.3s;
        }

        button:hover {
          background-color: #0062c1;
        }

        .error-message {
          color: #ff3b30;
          margin-top: 1rem;
          font-size: 0.9rem;
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <h1>R2管理</h1>
        <form action="/login" method="post">
          ${next ? `<input type="hidden" name="next" value="${escapeHtml(next)}">` : ''}
          <div class="input-group">
            <input type="password" name="key" placeholder="请输入访问密钥" required>
          </div>
          <button type="submit">登录</button>
          ${errorMessage ? `<p class="error-message">${escapeHtml(errorMessage)}</p>` : ''}
        </form>
      </div>
    </body>
    </html>
    `;

	return new Response(html, {
		headers: {'Content-Type': 'text/html; charset=utf-8'}
	});
}

function serveUploadPage() {
	const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>R2管理 - 上传</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
          background-color: #fbfbfd;
          color: #1d1d1f;
          min-height: 100vh;
        }

        .modal {

          display: none;

          position: fixed;

          top: 0;

          left: 0;

          width: 100%;

          height: 100%;

          background-color: rgba(0, 0, 0, 0.9);

          z-index: 9999;

          align-items: center;

          justify-content: center;

        }

        .modal.show {

          display: flex;

        }

        header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1rem 2rem;
          background-color: rgba(255, 255, 255, 0.8);
          backdrop-filter: blur(10px);
          -webkit-backdrop-filter: blur(10px);
          border-bottom: 1px solid #d2d2d7;
          position: sticky;
          top: 0;
          z-index: 100;
        }

        .logo {
          font-weight: 600;
          font-size: 1.5rem;
        }

        .nav-links a {
          color: #0071e3;
          font-weight: 500;
          text-decoration: none;
          margin-left: 1.5rem;
          transition: opacity 0.3s;
        }

        .nav-links a:hover {
          opacity: 0.7;
        }

        main {
          max-width: 900px;
          margin: 3rem auto;
          padding: 0 1.5rem;
        }

        .upload-container {
          background-color: white;
          border-radius: 18px;
          box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
          padding: 2.5rem;
          margin-bottom: 2rem;
        }

        h1 {
          font-weight: 600;
          font-size: 1.8rem;
          margin-bottom: 1.5rem;
        }

        .dropzone {
          border: 2px dashed #d2d2d7;
          border-radius: 12px;
          padding: 3rem 1.5rem;
          text-align: center;
          cursor: pointer;
          transition: all 0.3s;
          margin-bottom: 1.5rem;
        }

        .dropzone:hover, .dropzone.active {
          border-color: #0071e3;
          background-color: rgba(0, 113, 227, 0.05);
        }

        .dropzone-icon {
          font-size: 3rem;
          color: #0071e3;
          margin-bottom: 1rem;
        }

        .path-input {
          margin-bottom: 1.5rem;
        }

        .path-input label {
          display: block;
          margin-bottom: 0.5rem;
          font-weight: 500;
        }

        input {
          width: 100%;
          padding: 0.8rem 1rem;
          border: 1px solid #d2d2d7;
          border-radius: 12px;
          font-size: 1rem;
          transition: border-color 0.3s;
        }

        input:focus {
          outline: none;
          border-color: #0071e3;
          box-shadow: 0 0 0 2px rgba(0, 113, 227, 0.2);
        }

        button {
          background-color: #0071e3;
          color: white;
          border: none;
          border-radius: 12px;
          padding: 0.8rem 2rem;
          font-size: 1rem;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.3s;
          display: block;
          width: 100%;
        }

        button:hover {
          background-color: #0062c1;
        }

        .selected-files {
          margin-top: 1.5rem;
        }

        .preview-item {
          display: flex;
          align-items: center;
          background-color: #f5f5f7;
          border-radius: 8px;
          padding: 0.5rem 1rem;
          margin-bottom: 0.5rem;
        }

        .preview-item .file-name {
          flex-grow: 1;
          margin-left: 0.5rem;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .preview-thumb {
          width: 40px;
          height: 40px;
          object-fit: cover;
          border-radius: 6px;
          flex-shrink: 0;
          background-color: #e8e8ed;
        }

        .preview-note {
          color: #34c759;
          font-size: 0.78rem;
          margin-left: 0.5rem;
          flex-shrink: 0;
        }

        .preview-item .remove-file {
          color: #ff3b30;
          background: none;
          border: none;
          cursor: pointer;
          font-size: 1rem;
          padding: 0.25rem;
          width: auto;
        }

        .fail-list { margin-top: 0.75rem; }
        .fail-item {
          color: #ff3b30;
          font-size: 0.85rem;
          margin-bottom: 0.35rem;
          word-break: break-all;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .progress {
          height: 6px;
          background-color: #e5e5ea;
          border-radius: 3px;
          overflow: hidden;
          margin: 0 0.5rem;
          width: 140px;
          flex-shrink: 0;
        }
        .progress-bar {
          height: 100%;
          background-color: #0071e3;
          width: 0;
          transition: width 0.2s;
        }
        .status-text {
          font-size: 0.78rem;
          color: #86868b;
          flex-shrink: 0;
          min-width: 34px;
          text-align: right;
        }
        .btn-retry {
          background-color: #ff9500;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 0.25rem 0.75rem;
          font-size: 0.8rem;
          cursor: pointer;
          flex-shrink: 0;
        }

        /* Success Modal Styles */
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: rgba(0, 0, 0, 0.5);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
          opacity: 0;
          visibility: hidden;
          transition: all 0.3s;
        }

        .modal-overlay.active {
          opacity: 1;
          visibility: visible;
        }

        .modal-content {
          background-color: white;
          border-radius: 18px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
          width: 90%;
          max-width: 500px;
          padding: 2rem;
          transform: translateY(-20px);
          transition: transform 0.3s;
        }

        .modal-overlay.active .modal-content {
          transform: translateY(0);
        }

        .modal-content {
		  max-height: 80vh;
		  overflow-y: auto;
		}

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1.5rem;
        }

        .modal-title {
          font-weight: 600;
          font-size: 1.5rem;
        }

        .modal-close {
          background: none;
          border: none;
          font-size: 1.5rem;
          cursor: pointer;
          padding: 0.25rem;
          width: auto;
        }

        .link-item {
          background-color: #f5f5f7;
          border-radius: 8px;
          padding: 1rem;
          margin-bottom: 1rem;
        }

        .link-item h3 {
          font-size: 1rem;
          margin-bottom: 0.5rem;
        }

        .link-value {
          display: flex;
          align-items: center;
          background-color: white;
          border-radius: 6px;
          border: 1px solid #d2d2d7;
          padding: 0.5rem;
        }

        .link-text {
          flex-grow: 1;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          font-family: monospace;
          font-size: 0.9rem;
          max-width: 20rem;
        }

        .copy-btn {
          background-color: #0071e3;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 0.25rem 0.75rem;
          font-size: 0.8rem;
          margin-left: 0.5rem;
          cursor: pointer;
          width: auto;
        }

        @media (max-width: 768px) {
          main { margin: 1.25rem auto; padding: 0 0.75rem; }
          .upload-container { padding: 1.25rem; }
          h1 { font-size: 1.4rem; }
          header { padding: 0.75rem 1rem; flex-wrap: wrap; gap: 0.5rem; }
          .dropzone { padding: 2rem 1rem; }
          button { min-height: 44px; }
          .link-text { max-width: 9rem; }
        }
      </style>
    </head>
    <body>
      <header>
        <div class="logo">R2管理</div>
        <div class="nav-links">
          <a href="/upload" class="active">上传图片</a>
          <a href="/gallery">图片管理</a>
          <a href="/logout">退出登录</a>
        </div>
      </header>

      <main>
        <div class="upload-container">
          <h1>上传图片</h1>
          <div class="dropzone" id="dropzone">
            <div class="dropzone-icon">📤</div>
            <p>拖拽文件到此处、点击选择，或直接 Ctrl+V 粘贴截图</p>
            <p class="sub-text">支持 JPG / PNG / GIF / WebP / BMP · 超过 500KB 的图片将自动在浏览器压缩为 WebP</p>
            <input type="file" id="fileInput" style="display: none;" accept="image/jpeg,image/png,image/gif,image/webp,image/bmp" multiple>
          </div>

          <div class="path-input">
            <label for="customPath">目标路径（可选，默认记住上次使用）</label>
            <input type="text" id="customPath" placeholder="例如: blog/images">
          </div>

          <div class="selected-files" id="selectedFiles"></div>

          <button id="uploadBtn" disabled>上传图片</button>
        </div>
      </main>

      <div class="modal-overlay" id="successModal">
        <div class="modal-content">
          <div class="modal-header">
            <h2 class="modal-title">上传成功</h2>
            <button class="modal-close" id="closeModal">×</button>
          </div>
          <div class="modal-body" id="modalContent">
            <!-- Links will be populated here -->
          </div>
        </div>
      </div>

      <script>
        document.addEventListener('DOMContentLoaded', () => {
          const dropzone = document.getElementById('dropzone');
          const fileInput = document.getElementById('fileInput');
          const selectedFilesContainer = document.getElementById('selectedFiles');
          const uploadBtn = document.getElementById('uploadBtn');
          const customPath = document.getElementById('customPath');
          const successModal = document.getElementById('successModal');
          const closeModal = document.getElementById('closeModal');
          const modalContent = document.getElementById('modalContent');

          const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'];
          const COMPRESSIBLE = ['image/jpeg', 'image/png', 'image/bmp'];
          const COMPRESS_THRESHOLD = 500 * 1024;

          // 待上传条目：{ file, previewUrl, compressedFrom }
          let selectedFiles = [];

          // 路径预填：URL ?path= 参数（图库"上传到此文件夹"跳转）> 上次使用 > 空
          const pageParams = new URLSearchParams(window.location.search);
          const pathParam = sanitizePath(pageParams.get('path') || '');
          customPath.value = pathParam || localStorage.getItem('r2_upload_path') || '';

          function sanitizePath(p) {
            if (!p) return '';
            const joined = p.split('/').map(s => s.trim()).filter(s => s && s !== '.' && s !== '..').join('/');
            return joined;
          }

          // Dropzone event listeners
          dropzone.addEventListener('click', () => fileInput.click());

          dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('active');
          });

          dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('active');
          });

          dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('active');
            handleFiles(e.dataTransfer.files);
          });

          fileInput.addEventListener('change', () => {
            handleFiles(fileInput.files);
            fileInput.value = '';
          });

          // 粘贴截图直传
          document.addEventListener('paste', (e) => {
            const files = e.clipboardData && e.clipboardData.files;
            if (files && files.length > 0) {
              e.preventDefault();
              handleFiles(files);
            }
          });

          function isAllowed(file) {
            return ALLOWED_TYPES.indexOf((file.type || '').toLowerCase()) !== -1;
          }

          function handleFiles(files) {
            const validFiles = Array.from(files).filter(isAllowed);

            if (validFiles.length === 0) {
              alert('只支持 JPG / PNG / GIF / WebP / BMP 格式的图片文件');
              return;
            }

            validFiles.forEach(file => {
              selectedFiles.push({ file: file, previewUrl: URL.createObjectURL(file), compressedFrom: 0 });
            });
            updateFilePreview();
            uploadBtn.disabled = selectedFiles.length === 0;
          }

          function updateFilePreview() {
            selectedFilesContainer.innerHTML = '';

            selectedFiles.forEach((entry, index) => {
              const item = document.createElement('div');
              item.className = 'preview-item';

              const thumb = document.createElement('img');
              thumb.className = 'preview-thumb';
              thumb.src = entry.previewUrl;
              thumb.alt = '';

              const nameDiv = document.createElement('div');
              nameDiv.className = 'file-name';
              nameDiv.textContent = entry.file.name;

              item.appendChild(thumb);
              item.appendChild(nameDiv);

              if (entry.compressedFrom > 0) {
                const note = document.createElement('span');
                note.className = 'preview-note';
                note.textContent = formatSize(entry.compressedFrom) + ' → ' + formatSize(entry.file.size);
                item.appendChild(note);
              }

              const removeBtn = document.createElement('button');
              removeBtn.className = 'remove-file';
              removeBtn.type = 'button';
              removeBtn.setAttribute('aria-label', '移除 ' + entry.file.name);
              removeBtn.textContent = '×';
              removeBtn.addEventListener('click', () => {
                URL.revokeObjectURL(entry.previewUrl);
                selectedFiles.splice(index, 1);
                updateFilePreview();
                uploadBtn.disabled = selectedFiles.length === 0;
              });
              item.appendChild(removeBtn);

              selectedFilesContainer.appendChild(item);
            });
          }

          function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
          }

          // P0-1 方案 A：>500KB 的可压缩格式在浏览器端转 WebP（服务端不再做转换）
          // P2-7：createImageBitmap 指定 imageOrientation: 'from-image' 顺带修正 EXIF 方向
          async function maybeCompress(entry) {
            const file = entry.file;
            const type = (file.type || '').toLowerCase();
            if (file.size <= COMPRESS_THRESHOLD || COMPRESSIBLE.indexOf(type) === -1) return entry;
            if (typeof createImageBitmap !== 'function') return entry;
            let bitmap = null;
            try {
              bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
            } catch (err1) {
              try { bitmap = await createImageBitmap(file); } catch (err2) { return entry; }
            }
            try {
              const w = bitmap.width, h = bitmap.height;
              const blob = await canvasToWebp(bitmap, w, h);
              if (bitmap.close) bitmap.close();
              if (blob && blob.size > 0 && blob.size < file.size) {
                const newName = file.name.replace(/\\.[^.]+$/, '') + '.webp';
                return {
                  file: new File([blob], newName, { type: 'image/webp' }),
                  previewUrl: entry.previewUrl,
                  compressedFrom: file.size
                };
              }
            } catch (err) {
              // 解码/编码失败时回退上传原图
            }
            return entry;
          }

          async function canvasToWebp(source, w, h) {
            if (typeof OffscreenCanvas !== 'undefined') {
              const canvas = new OffscreenCanvas(w, h);
              canvas.getContext('2d').drawImage(source, 0, 0);
              return await canvas.convertToBlob({ type: 'image/webp', quality: 0.8 });
            }
            const canvas = document.createElement('canvas');
            canvas.width = w; canvas.height = h;
            canvas.getContext('2d').drawImage(source, 0, 0);
            return await new Promise(resolve => canvas.toBlob(resolve, 'image/webp', 0.8));
          }

          // 上传队列：3 路并发、XHR 单文件进度、失败可重试
          let uploadInProgress = false;
          let lastResults = [];

          uploadBtn.addEventListener('click', async () => {
            if (selectedFiles.length === 0 || uploadInProgress) return;

            uploadInProgress = true;
            uploadBtn.disabled = true;

            const pathValue = sanitizePath(customPath.value.trim());
            if (pathValue) {
              localStorage.setItem('r2_upload_path', pathValue);
            } else {
              localStorage.removeItem('r2_upload_path');
            }

            // 1) 顺序预压缩（避免并发解码占用内存），刷新压缩状态提示
            for (let i = 0; i < selectedFiles.length; i++) {
              selectedFiles[i] = await maybeCompress(selectedFiles[i]);
              updateFilePreview();
            }

            // 2) 并发上传池
            const total = selectedFiles.length;
            let doneCount = 0;
            uploadBtn.textContent = '上传中 0/' + total;
            const results = new Array(total).fill(null);
            let nextIndex = 0;
            async function poolWorker() {
              while (nextIndex < total) {
                const idx = nextIndex++;
                results[idx] = await uploadEntry(selectedFiles[idx], idx, pathValue);
                doneCount++;
                uploadBtn.textContent = '上传中 ' + doneCount + '/' + total;
              }
            }
            const workers = [];
            for (let i = 0; i < Math.min(3, total); i++) workers.push(poolWorker());
            await Promise.all(workers);

            lastResults = results;
            renderResults();

            uploadBtn.disabled = false;
            uploadBtn.textContent = '上传图片';
            uploadInProgress = false;
          });

          function uploadEntry(entry, idx, pathValue) {
            return new Promise(resolve => {
              const xhr = new XMLHttpRequest();
              xhr.open('POST', '/api/upload', true);
              xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) setItemProgress(idx, Math.round(e.loaded / e.total * 100));
              };
              xhr.onload = () => {
                let data = {};
                try { data = JSON.parse(xhr.responseText); } catch (e) {}
                if (xhr.status >= 200 && xhr.status < 300 && data.success) {
                  setItemProgress(idx, 100);
                  resolve({ entry: entry, ok: true, key: data.key, url: data.url, name: entry.file.name, size: entry.file.size, compressedFrom: entry.compressedFrom });
                } else {
                  setItemFailed(idx);
                  resolve({ entry: entry, ok: false, name: entry.file.name, message: data.message || ('上传失败 (' + xhr.status + ')') });
                }
              };
              xhr.onerror = () => {
                setItemFailed(idx);
                resolve({ entry: entry, ok: false, name: entry.file.name, message: '网络错误' });
              };
              const formData = new FormData();
              formData.append('file', entry.file);
              formData.append('path', pathValue);
              xhr.send(formData);
            });
          }

          function ensureProgressRow(item) {
            if (!item.querySelector('.progress')) {
              const p = document.createElement('div');
              p.className = 'progress';
              const bar = document.createElement('div');
              bar.className = 'progress-bar';
              p.appendChild(bar);
              const status = document.createElement('span');
              status.className = 'status-text';
              item.appendChild(p);
              item.appendChild(status);
            }
            return item;
          }

          function setItemProgress(idx, pct) {
            const item = selectedFilesContainer.children[idx];
            if (!item) return;
            ensureProgressRow(item);
            item.querySelector('.progress-bar').style.width = pct + '%';
            item.querySelector('.status-text').textContent = pct + '%';
            item.querySelector('.status-text').style.color = '';
          }

          function setItemFailed(idx) {
            const item = selectedFilesContainer.children[idx];
            if (!item) return;
            ensureProgressRow(item);
            const st = item.querySelector('.status-text');
            st.textContent = '失败';
            st.style.color = '#ff3b30';
          }

          function formatLinkText(url, fmt) {
            if (fmt === 'md') return '![img](' + url + ')';
            if (fmt === 'html') return '<img src="' + url + '" />';
            if (fmt === 'bbcode') return '[img]' + url + '[/img]';
            return url;
          }

          function copyText(text, btn) {
            const done = () => {
              if (btn) {
                const original = btn.textContent;
                btn.textContent = '已复制';
                setTimeout(() => { btn.textContent = original; }, 1500);
              }
            };
            if (navigator.clipboard && window.isSecureContext) {
              navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
            } else {
              fallbackCopy(text, done);
            }
          }

          function fallbackCopy(text, done) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch (e) {}
            document.body.removeChild(ta);
            done();
          }

          // 四格式外链复制组件（直链 / Markdown / HTML / BBCode）
          function appendLinkRows(container, url) {
            const formats = [['直接链接', 'url'], ['Markdown', 'md'], ['HTML', 'html'], ['BBCode', 'bbcode']];
            formats.forEach(pair => {
              const section = document.createElement('div');
              section.className = 'link-section';

              const h4 = document.createElement('h4');
              h4.textContent = pair[0];
              section.appendChild(h4);

              const value = document.createElement('div');
              value.className = 'link-value';

              const text = document.createElement('span');
              text.className = 'link-text';
              text.textContent = formatLinkText(url, pair[1]);
              value.appendChild(text);

              const btn = document.createElement('button');
              btn.className = 'copy-btn';
              btn.type = 'button';
              btn.textContent = '复制';
              btn.addEventListener('click', () => copyText(formatLinkText(url, pair[1]), btn));
              value.appendChild(btn);

              section.appendChild(value);
              container.appendChild(section);
            });
          }

          // 渲染上传结果（成功项 + 失败项可重试）
          function renderResults() {
            modalContent.innerHTML = '';

            const successful = lastResults.filter(r => r && r.ok);
            const failed = lastResults.filter(r => r && !r.ok);

            if (successful.length === 0 && failed.length === 0) return;

            if (successful.length === 0) {
              const p = document.createElement('p');
              p.textContent = '所有上传都失败了，可逐个重试。';
              modalContent.appendChild(p);
            } else {
              successful.forEach(result => {
                const item = document.createElement('div');
                item.className = 'link-item';

                const h3 = document.createElement('h3');
                let title = result.name;
                if (result.compressedFrom > 0) {
                  title += '（已压缩 ' + formatSize(result.compressedFrom) + ' → ' + formatSize(result.size || 0) + '）';
                }
                h3.textContent = title;
                item.appendChild(h3);

                appendLinkRows(item, result.url);
                modalContent.appendChild(item);
              });
            }

            if (failed.length > 0) {
              const failList = document.createElement('div');
              failList.className = 'fail-list';
              failed.forEach(result => {
                const item = document.createElement('div');
                item.className = 'fail-item';
                const text = document.createElement('span');
                text.textContent = '✕ ' + result.name + '：' + result.message;
                item.appendChild(text);
                const btn = document.createElement('button');
                btn.className = 'btn-retry';
                btn.type = 'button';
                btn.textContent = '重试';
                btn.addEventListener('click', () => retryOne(result));
                item.appendChild(btn);
                failList.appendChild(item);
              });
              modalContent.appendChild(failList);
            }

            successModal.classList.add('active');
          }

          // 单文件重试（复用已压缩好的文件对象）
          async function retryOne(result) {
            const idx = selectedFiles.indexOf(result.entry);
            const fresh = await uploadEntry(result.entry, idx >= 0 ? idx : 0, sanitizePath(customPath.value.trim()));
            Object.assign(result, fresh, { entry: result.entry });
            renderResults();
          }

          // 关闭弹窗时清理预览与队列状态
          function closeModalCleanup() {
            successModal.classList.remove('active');
            selectedFiles.forEach(entry => URL.revokeObjectURL(entry.previewUrl));
            selectedFiles = [];
            lastResults = [];
            updateFilePreview();
            uploadBtn.disabled = true;
          }

          closeModal.addEventListener('click', closeModalCleanup);

          // Close modal when clicking outside
          successModal.addEventListener('click', (e) => {
            if (e.target === successModal) {
              closeModalCleanup();
            }
          });
        });
      </script>
    </body>
    </html>
    `;

	return new Response(html, {
		headers: {'Content-Type': 'text/html; charset=utf-8'}
	});
}

function serveGalleryPage() {
	const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>R2管理</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
        }
        body {
            background-color: #f5f7fa;
            color: #333;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e1e4e8;
        }
        .header h1 {
            font-size: 24px;
            color: #2c3e50;
        }
        .header-buttons {
            display: flex;
            gap: 10px;
        }
        .btn {
            background-color: #4b6bfb;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.2s;
            text-decoration: none;
        }
        .btn:hover {
            background-color: #3a54d6;
        }
        .btn-danger {
            background-color: #e74c3c;
        }
        .btn-danger:hover {
            background-color: #c0392b;
        }
        .btn-secondary {
            background-color: #7f8c8d;
        }
        .btn-secondary:hover {
            background-color: #636e72;
        }
        .breadcrumb {
            margin-bottom: 20px;
            padding: 10px;
            background-color: white;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .breadcrumb a {
            color: #4b6bfb;
            text-decoration: none;
        }
        .breadcrumb a:hover {
            text-decoration: underline;
        }
        .breadcrumb .separator {
            margin: 0 8px;
            color: #95a5a6;
        }
        .gallery-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .select-all-container {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .select-all-checkbox {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 20px;
        }
        .item {
            background-color: white;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: transform 0.2s;
            position: relative;
        }
        .item:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .directory {
            padding: 25px 15px;
            text-align: center;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }
        .directory-icon {
            font-size: 40px;
            color: #f39c12;
        }
        .file {
            cursor: pointer;
            position: relative;
        }
        .file-image {
            width: 100%;
            aspect-ratio: 1;
            object-fit: cover;
            display: block;
        }
        .file-info {
            padding: 10px;
            font-size: 13px;
            border-top: 1px solid #eee;
        }
        .file-name {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 5px;
        }
        .file-size {
            color: #7f8c8d;
        }
        .checkbox {
            position: absolute;
            top: 10px;
            left: 10px;
            height: 20px;
            width: 20px;
            background-color: white;
            border: 2px solid #ddd;
            border-radius: 3px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1;
        }
        .file.selected .checkbox {
            background-color: #4b6bfb;
            border-color: #4b6bfb;
        }
        .checkbox:hover {
            border-color: #4b6bfb;
        }
        .file.selected .checkbox:after {
            content: "✓";
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 40px 0;
            color: #7f8c8d;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            z-index: 100;
            align-items: center;
            justify-content: center;
        }
        .modal-content {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            width: 400px;
            max-width: 90%;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .close {
            font-size: 24px;
            cursor: pointer;
            color: #7f8c8d;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }
        .form-control {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }
        .loading {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.3);
            z-index: 200;
            align-items: center;
            justify-content: center;
        }
        .loading-spinner {
            width: 50px;
            height: 50px;
            border: 5px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background-color: #2ecc71;
            color: white;
            border-radius: 4px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
            transform: translateX(150%);
            transition: transform 0.3s ease-out;
            z-index: 300;
        }
        .notification.error {
            background-color: #e74c3c;
        }
        .notification.show {
            transform: translateX(0);
        }
        .load-more-container { margin-top: 10px; }
        /* 悬浮操作条（复制/下载，触屏常显） */
        .file-actions {
            position: absolute;
            top: 10px;
            right: 10px;
            display: flex;
            gap: 6px;
            opacity: 0;
            transition: opacity 0.2s;
            z-index: 2;
        }
        .file:hover .file-actions,
        .file:focus-within .file-actions {
            opacity: 1;
        }
        .action-btn {
            width: 32px;
            height: 32px;
            min-height: 0;
            border: none;
            border-radius: 6px;
            background-color: rgba(255,255,255,0.92);
            cursor: pointer;
            font-size: 15px;
            line-height: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 1px 4px rgba(0,0,0,0.25);
            padding: 0;
            color: #2c3e50;
        }
        .action-btn:hover { background-color: #ffffff; transform: scale(1.05); }
        /* 文件夹卡片悬浮删除 */
        .dir-delete {
            position: absolute;
            top: 8px;
            right: 8px;
            opacity: 0;
            transition: opacity 0.2s;
        }
        .item.directory:hover .dir-delete,
        .item.directory:focus-within .dir-delete { opacity: 1; }
        /* Lightbox 大图预览 */
        .lightbox {
            display: none;
            position: fixed;
            inset: 0;
            background-color: rgba(0,0,0,0.92);
            z-index: 400;
            align-items: center;
            justify-content: center;
            flex-direction: column;
        }
        .lightbox.show { display: flex; }
        .lightbox-img {
            max-width: 92vw;
            max-height: 72vh;
            object-fit: contain;
            border-radius: 4px;
        }
        .lightbox-info {
            color: #eeeeee;
            margin-top: 10px;
            font-size: 13px;
            text-align: center;
            max-width: 90vw;
            word-break: break-all;
        }
        .lightbox-controls {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .lightbox-controls .btn { padding: 10px 14px; }
        .lightbox-nav {
            position: fixed;
            top: 50%;
            transform: translateY(-50%);
            font-size: 40px;
            color: white;
            background: none;
            border: none;
            cursor: pointer;
            padding: 20px;
            user-select: none;
            line-height: 1;
        }
        .lightbox-nav.prev { left: 10px; }
        .lightbox-nav.next { right: 10px; }
        .lightbox-close {
            position: fixed;
            top: 14px;
            right: 20px;
            font-size: 34px;
            color: white;
            background: none;
            border: none;
            cursor: pointer;
            line-height: 1;
        }
        /* 搜索/排序控件 */
        .controls-right {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-left: auto;
        }
        .search-input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            width: 200px;
        }
        .sort-select {
            padding: 8px 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            background: white;
            cursor: pointer;
        }
        .view-toggle { white-space: nowrap; }

        /* 列表视图 */
        .gallery.list-view {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .gallery.list-view .item.file {
            display: flex;
            align-items: center;
            padding: 6px 10px;
        }
        .gallery.list-view .file-image {
            width: 48px;
            height: 48px;
            aspect-ratio: auto;
            border-radius: 4px;
            margin: 0;
        }
        .gallery.list-view .file-info {
            border-top: none;
            margin-left: 12px;
            flex: 1;
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 0;
            min-width: 0;
        }
        .gallery.list-view .file-name {
            flex: 1;
            margin: 0;
        }
        .gallery.list-view .file-actions {
            position: static;
            opacity: 1;
        }
        .gallery.list-view .checkbox {
            position: static;
            margin-right: 10px;
            flex-shrink: 0;
        }

        /* 重命名提示 */
        .rename-warn {
            color: #e67e22;
            font-size: 13px;
            margin: 10px 0 0;
        }

        /* 统计面板 */
        .stats-content { text-align: left; }
        .stats-big {
            font-size: 22px;
            font-weight: 600;
            color: #2c3e50;
            margin: 8px 0 2px;
        }
        .stats-label { color: #7f8c8d; font-size: 13px; }
        .stats-row {
            display: flex;
            gap: 28px;
            justify-content: center;
            margin: 10px 0 18px;
            flex-wrap: wrap;
        }
        .stats-table { width: 100%; border-collapse: collapse; margin-top: 6px; }
        .stats-table th, .stats-table td {
            text-align: left;
            padding: 6px 8px;
            border-bottom: 1px solid #eee;
            font-size: 13px;
        }
        .stats-table th { color: #7f8c8d; font-weight: 500; }

        /* 回收站模式辅助类 */
        .hidden { display: none !important; }
        .btn-active {
            background: #34c759 !important;
            color: white !important;
        }

        /* 回收站视图 */
        .trash-view .trash-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 10px;
            border-bottom: 1px solid #eee;
            background: #fafafa;
            border-radius: 6px;
            margin-bottom: 6px;
        }
        .trash-view .trash-name {
            flex: 1;
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 14px;
        }
        .trash-view .trash-date {
            color: #86868b;
            font-size: 12px;
            flex-shrink: 0;
        }
        .trash-view .btn-restore {
            background: #34c759;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 5px 12px;
            font-size: 13px;
            cursor: pointer;
            flex-shrink: 0;
        }
        .trash-view .btn-purge-one {
            background: #ff3b30;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 5px 12px;
            font-size: 13px;
            cursor: pointer;
            flex-shrink: 0;
        }
        .trash-toolbar {
            display: flex;
            gap: 8px;
            align-items: center;
            margin: 10px 0;
        }
        .trash-toolbar .spacer { flex: 1; }

        /* 无障碍：键盘焦点可见 */
        a:focus-visible, button:focus-visible, [tabindex]:focus-visible,
        input:focus-visible, .checkbox:focus-visible {
            outline: 2px solid #4b6bfb;
            outline-offset: 2px;
        }
        /* 移动端适配（此前全站零 @media） */
        @media (max-width: 768px) {
            body { padding: 10px; }
            .header {
                flex-direction: column;
                gap: 10px;
                align-items: stretch;
                text-align: center;
            }
            .header-buttons { justify-content: center; flex-wrap: wrap; }
            .btn { padding: 12px 16px; font-size: 15px; }
            .gallery { grid-template-columns: repeat(2, 1fr); gap: 10px; }
            .file-actions { opacity: 1; }
            .action-btn { width: 40px; height: 40px; font-size: 17px; }
            .checkbox { width: 26px; height: 26px; top: 6px; left: 6px; }
            .dir-delete { opacity: 1; }
            .modal-content { width: 94%; }
            .lightbox-nav { font-size: 30px; padding: 12px; }
            .gallery-controls { flex-wrap: wrap; gap: 8px; }
            .controls-right { flex-wrap: wrap; margin-left: 0; width: 100%; justify-content: center; }
            .search-input { flex: 1; min-width: 140px; width: auto; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>R2管理</h1>
            <div class="header-buttons">
                <a id="navUploadLink" href="/upload" class="btn">上传图片</a>
                <button id="newFolderBtn" class="btn btn-secondary">新建文件夹</button>
                <button id="statsBtn" class="btn btn-secondary">统计</button>
                <button id="trashBtn" class="btn btn-secondary">回收站</button>
                <button id="deleteBtn" class="btn btn-danger" disabled>删除所选</button>
                <a href="/logout" class="btn btn-secondary">退出登录</a>
            </div>
        </div>

        <div class="breadcrumb" id="breadcrumb">
            <a href="/gallery" data-path="">首页</a>
        </div>

        <div class="gallery-controls">
            <div class="select-all-container">
                <input type="checkbox" id="selectAllCheckbox" class="select-all-checkbox">
                <label for="selectAllCheckbox">全选</label>
            </div>
            <div class="controls-right">
                <input type="search" id="searchInput" class="search-input" placeholder="搜索当前已加载图片…" aria-label="搜索图片">
                <select id="sortSelect" class="sort-select" aria-label="排序方式">
                    <option value="time-desc">最新在前</option>
                    <option value="time-asc">最旧在前</option>
                    <option value="name-asc">名称 A→Z</option>
                    <option value="name-desc">名称 Z→A</option>
                </select>
                <button id="viewToggle" class="btn btn-secondary view-toggle" type="button" aria-pressed="false">☰ 列表</button>
            </div>
        </div>

        <div class="gallery" id="gallery">
            <!-- 内容将通过JavaScript动态加载 -->
        </div>

        <div id="loadMoreContainer" class="load-more-container" style="text-align: center; margin-top: 20px; display: none;">
            <button onclick="loadMore()" class="btn">加载更多</button>
        </div>
    </div>

    <!-- 大图预览（Lightbox） -->
    <div class="lightbox" id="lightbox" role="dialog" aria-modal="true" aria-hidden="true" aria-label="图片预览">
        <button class="lightbox-close" id="lbClose" type="button" aria-label="关闭预览">&times;</button>
        <button class="lightbox-nav prev" id="lbPrev" type="button" aria-label="上一张">&#8249;</button>
        <img class="lightbox-img" id="lbImg" alt="">
        <button class="lightbox-nav next" id="lbNext" type="button" aria-label="下一张">&#8250;</button>
        <div class="lightbox-info" id="lbInfo"></div>
        <div class="lightbox-controls" id="lbControls">
            <button class="btn" type="button" data-fmt="url">复制直链</button>
            <button class="btn" type="button" data-fmt="md">复制 Markdown</button>
            <button class="btn" type="button" data-fmt="html">复制 HTML</button>
            <button class="btn" type="button" data-fmt="bbcode">复制 BBCode</button>
            <button class="btn" type="button" id="lbDownload">下载</button>
        </div>
    </div>

    <!-- 新建文件夹的模态框 -->
    <div class="modal" id="folderModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>新建文件夹</h3>
                <span class="close">&times;</span>
            </div>
            <div class="form-group">
                <label for="folderName">文件夹名称</label>
                <input type="text" id="folderName" class="form-control" placeholder="请输入文件夹名称">
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary close-modal">取消</button>
                <button id="createFolderBtn" class="btn">创建</button>
            </div>
        </div>
    </div>

    <!-- 重命名/移动的模态框 -->
    <div class="modal" id="renameModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>重命名 / 移动</h3>
                <span class="close">&times;</span>
            </div>
            <div class="form-group">
                <label for="renameName">文件名</label>
                <input type="text" id="renameName" class="form-control">
            </div>
            <div class="form-group">
                <label for="renameFolder">目标文件夹（留空 = 根目录）</label>
                <input type="text" id="renameFolder" class="form-control" placeholder="例如: blog/images">
            </div>
            <p class="rename-warn">⚠ 旧直链将失效（CDN 缓存最长一年内仍可能命中旧内容）</p>
            <div class="modal-footer">
                <button class="btn btn-secondary close-modal">取消</button>
                <button id="renameConfirmBtn" class="btn">确定</button>
            </div>
        </div>
    </div>

    <!-- 统计的模态框 -->
    <div class="modal" id="statsModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>存储用量统计</h3>
                <span class="close">&times;</span>
            </div>
            <div id="statsContent" class="stats-content">加载中…</div>
        </div>
    </div>

    <!-- 清空回收站确认模态框 -->
    <div class="modal" id="purgeModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>清空回收站</h3>
                <span class="close">&times;</span>
            </div>
            <p>将<b>彻底删除</b>回收站内的全部文件（最多 5000 项），此操作不可撤销。确定继续？</p>
            <div class="modal-footer">
                <button class="btn btn-secondary close-modal">取消</button>
                <button id="purgeConfirmBtn" class="btn btn-danger">彻底删除</button>
            </div>
        </div>
    </div>

    <!-- 加载指示器 -->
    <div class="loading" id="loading">
        <div class="loading-spinner"></div>
    </div>

    <!-- 通知提示 -->
    <div class="notification" id="notification"></div>

    <script>
        // 全局变量
        let currentPath = '';
        let selectedFiles = [];
        let allFiles = [];
        let sortMode = 'time-desc';
        let searchQuery = '';

        // 规范化客户端路径：'blog/images' → 'blog/images/'，'' 保持为空；拒绝 .. 等片段
        function normalizeClientPath(p) {
            if (!p) return '';
            const joined = String(p).split('/').map(s => s.trim()).filter(s => s && s !== '.' && s !== '..').join('/');
            return joined ? joined + '/' : '';
        }

        // 客户端过滤 + 排序（作用于已加载的文件；默认服务端已按时间倒序返回）
        function applyClientFilters() {
            let list = allFiles;
            if (searchQuery) {
                const q = searchQuery.toLowerCase();
                list = list.filter(f => f.name.toLowerCase().indexOf(q) !== -1);
            }
            if (sortMode === 'time-asc') {
                list = list.slice().sort((a, b) => new Date(a.uploaded) - new Date(b.uploaded));
            } else if (sortMode === 'name-asc') {
                list = list.slice().sort((a, b) => a.name.localeCompare(b.name, 'zh-Hans-CN'));
            } else if (sortMode === 'name-desc') {
                list = list.slice().sort((a, b) => b.name.localeCompare(a.name, 'zh-Hans-CN'));
            }
            return list;
        }

        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', () => {
            // 深链接：从 URL ?path= 恢复文件夹位置
            const params = new URLSearchParams(window.location.search);
            currentPath = normalizeClientPath(params.get('path') || '');

            // 加载初始数据
            loadGallery();

            // 绑定事件
            document.getElementById('deleteBtn').addEventListener('click', deleteSelectedFiles);
            document.getElementById('newFolderBtn').addEventListener('click', () => showModal('folderModal'));
            document.getElementById('createFolderBtn').addEventListener('click', createFolder);
            document.getElementById('selectAllCheckbox').addEventListener('change', toggleSelectAll);

            // 搜索过滤（客户端，作用于已加载文件）
            const searchInput = document.getElementById('searchInput');
            let searchTimer;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimer);
                searchTimer = setTimeout(() => {
                    searchQuery = searchInput.value.trim();
                    renderGallery(visibleDirectories(), applyClientFilters());
                }, 150);
            });

            // 排序切换（客户端，状态进 URL）
            const sortSelect = document.getElementById('sortSelect');
            const urlSort = new URLSearchParams(window.location.search).get('sort');
            if (urlSort && ['time-desc', 'time-asc', 'name-asc', 'name-desc'].indexOf(urlSort) !== -1) {
                sortMode = urlSort;
                sortSelect.value = urlSort;
            }
            sortSelect.addEventListener('change', () => {
                sortMode = sortSelect.value;
                const url = new URL(window.location);
                url.searchParams.set('sort', sortMode);
                window.history.replaceState({}, '', url);
                renderGallery(visibleDirectories(), applyClientFilters());
            });

            // 网格/列表视图切换（记忆在 localStorage）
            const viewToggle = document.getElementById('viewToggle');
            const savedView = localStorage.getItem('r2_view_mode');
            if (savedView === 'list') {
                setViewMode('list');
            }
            viewToggle.addEventListener('click', () => {
                setViewMode(document.getElementById('gallery').classList.contains('list-view') ? 'grid' : 'list');
            });

            // 统计面板
            document.getElementById('statsBtn').addEventListener('click', openStats);

            // 回收站
            document.getElementById('trashBtn').addEventListener('click', openTrash);
            document.getElementById('purgeConfirmBtn').addEventListener('click', purgeAllTrash);

            // 重命名/移动
            document.getElementById('renameConfirmBtn').addEventListener('click', confirmRename);

            // 关闭模态框
            const closeButtons = document.querySelectorAll('.close, .close-modal');
            closeButtons.forEach(button => {
                button.addEventListener('click', () => {
                    document.querySelectorAll('.modal').forEach(modal => {
                        modal.style.display = 'none';
                    });
                });
            });

            // 点击模态框外部关闭
			document.querySelectorAll('.modal').forEach(modal => {
				modal.addEventListener('click', (e) => {
					if (e.target instanceof Element && e.target === modal) {
						modal.style.display = 'none';
					}
				});
			});

            // Lightbox 事件
            document.getElementById('lbClose').addEventListener('click', closeLightbox);
            document.getElementById('lbPrev').addEventListener('click', () => stepLightbox(-1));
            document.getElementById('lbNext').addEventListener('click', () => stepLightbox(1));
            document.getElementById('lbDownload').addEventListener('click', () => {
                const file = currentLightboxFile();
                if (file) downloadFile(file);
            });
            document.querySelectorAll('#lbControls [data-fmt]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const file = currentLightboxFile();
                    if (file) copyText(formatLinkText(file.url, btn.dataset.fmt), btn);
                });
            });
            document.getElementById('lightbox').addEventListener('click', (e) => {
                if (e.target instanceof Element && e.target.id === 'lightbox') closeLightbox();
            });

            // 键盘：Esc 关闭、←/→ 切换
            document.addEventListener('keydown', (e) => {
                const lightbox = document.getElementById('lightbox');
                if (!lightbox.classList.contains('show')) return;
                if (e.key === 'Escape') closeLightbox();
                if (e.key === 'ArrowLeft') stepLightbox(-1);
                if (e.key === 'ArrowRight') stepLightbox(1);
            });

            // 浏览器前进/后退：按 URL 恢复文件夹位置
            window.addEventListener('popstate', () => {
                const p = new URLSearchParams(window.location.search).get('path') || '';
                currentPath = normalizeClientPath(p);
                currentCursor = null;
                loadGallery();
            });
        });

        let currentCursor = null;
        let hasMore = false;
        let isLoading = false;
        let lastDirs = [];

        function visibleDirectories() {
            return lastDirs;
        }

        // 视图模式切换（网格/列表，记忆在 localStorage）
        function setViewMode(mode) {
            const gallery = document.getElementById('gallery');
            const btn = document.getElementById('viewToggle');
            if (mode === 'list') {
                gallery.classList.add('list-view');
                btn.textContent = '⊞ 网格';
                btn.setAttribute('aria-pressed', 'true');
                localStorage.setItem('r2_view_mode', 'list');
            } else {
                gallery.classList.remove('list-view');
                btn.textContent = '☰ 列表';
                btn.setAttribute('aria-pressed', 'false');
                localStorage.setItem('r2_view_mode', 'grid');
            }
        }

        // 更新"上传图片"导航链接，携带当前文件夹（配合上传页 ?path= 预填）
        function updateUploadLink() {
            const link = document.getElementById('navUploadLink');
            link.href = currentPath ? '/upload?path=' + encodeURIComponent(currentPath.replace(/\\/$/, '')) : '/upload';
        }

        // 切换文件夹（带 URL 深链接）
        function navigateTo(path) {
            currentPath = normalizeClientPath(path);
            currentCursor = null;
            const url = new URL(window.location);
            if (currentPath) {
                url.searchParams.set('path', currentPath.replace(/\\/$/, ''));
            } else {
                url.searchParams.delete('path');
            }
            window.history.pushState({}, '', url);
            loadGallery();
        }

        // 加载画廊内容
        async function loadGallery() {
            showLoading(true);
            closeLightbox();
            try {
                let apiUrl = '/api/list?prefix=' + encodeURIComponent(currentPath) + '&limit=20&all=1';
                if (currentCursor) {
                    apiUrl += '&cursor=' + encodeURIComponent(currentCursor);
                }
                const response = await fetch(apiUrl);
                if (response.status === 401) {
                    window.location.href = '/?next=%2Fgallery';
                    return;
                }
                const data = await response.json();

                // 保存全部文件列表
                allFiles = data.files;
                lastDirs = data.prefix;

                // 更新面包屑导航
                updateBreadcrumb();
                updateUploadLink();

                // 渲染文件夹和文件（经客户端过滤/排序）
                renderGallery(data.prefix, applyClientFilters());

                currentCursor = data.cursor;
                hasMore = data.hasMore;

                // 更新加载更多按钮
                const loadMoreContainer = document.getElementById('loadMoreContainer');
                loadMoreContainer.style.display = hasMore ? 'block' : 'none';

                // 重置选中状态
                selectedFiles = [];
                updateDeleteButton();
                document.getElementById('selectAllCheckbox').checked = false;
            } catch (error) {
                console.error('加载失败:', error);
                showNotification('加载失败，请重试', true);
            } finally {
                showLoading(false);
            }
        }

        // 加载更多（保留跨页已勾选项）
        async function loadMore() {
            if (!hasMore || isLoading) return;
            isLoading = true;
            try {
                let apiUrl = '/api/list?prefix=' + encodeURIComponent(currentPath) + '&limit=20&all=1';
                if (currentCursor) {
                    apiUrl += '&cursor=' + encodeURIComponent(currentCursor);
                }
                const response = await fetch(apiUrl);
                const data = await response.json();

                // 添加更多文件
                allFiles = allFiles.concat(data.files);
                lastDirs = data.prefix;
                renderGallery(data.prefix, applyClientFilters());

                currentCursor = data.cursor;
                hasMore = data.hasMore;

                const loadMoreContainer = document.getElementById('loadMoreContainer');
                if (!hasMore) {
                    loadMoreContainer.style.display = 'none';
                }
            } catch (error) {
                console.error('加载更多失败:', error);
                showNotification('加载失败，请重试', true);
            } finally {
                isLoading = false;
            }
        }

        // 更新面包屑导航
        function updateBreadcrumb() {
            const breadcrumb = document.getElementById('breadcrumb');
            breadcrumb.innerHTML = '';

            // 添加首页链接
            const homeLink = document.createElement('a');
            homeLink.href = '/gallery';
            homeLink.textContent = '首页';
            homeLink.addEventListener('click', (e) => {
                e.preventDefault();
                navigateTo('');
            });
            breadcrumb.appendChild(homeLink);

            // 如果当前不在首页，则添加路径
            if (currentPath) {
                const pathParts = currentPath.replace(/\\/$/, '').split('/').filter(p => p);
                let path = '';

                pathParts.forEach((part, index) => {
                    path = index === 0 ? part : path + '/' + part;

                    const separator = document.createElement('span');
                    separator.className = 'separator';
                    separator.textContent = ' / ';
                    breadcrumb.appendChild(separator);

                    const link = document.createElement('a');
                    link.href = '/gallery?path=' + encodeURIComponent(path);
                    link.textContent = part;

                    if (index === pathParts.length - 1) {
                        link.style.color = '#333';
                        link.style.textDecoration = 'none';
                        link.style.pointerEvents = 'none';
                    } else {
                        const target = path;
                        link.addEventListener('click', (e) => {
                            e.preventDefault();
                            navigateTo(target);
                        });
                    }
                    breadcrumb.appendChild(link);
                });
            }
        }

        // 悬浮操作按钮
        function actionBtn(icon, title, onClick) {
            const b = document.createElement('button');
            b.className = 'action-btn';
            b.type = 'button';
            b.textContent = icon;
            b.title = title;
            b.setAttribute('aria-label', title);
            b.addEventListener('click', (e) => {
                e.stopPropagation();
                onClick();
            });
            return b;
        }

        // 渲染画廊内容（DOM 方式构建，杜绝 innerHTML 注入）
        function renderGallery(directories, files) {
            const gallery = document.getElementById('gallery');
            gallery.innerHTML = '';

            // 渲染文件夹
            directories.forEach(dir => {
                const dirElement = document.createElement('div');
                dirElement.className = 'item directory';
                dirElement.tabIndex = 0;
                dirElement.setAttribute('role', 'button');
                dirElement.setAttribute('aria-label', '打开文件夹 ' + dir.name);

                const icon = document.createElement('div');
                icon.className = 'directory-icon';
                icon.textContent = '📁';

                const name = document.createElement('div');
                name.className = 'file-name';
                name.textContent = dir.name;

                const del = document.createElement('button');
                del.className = 'action-btn dir-delete';
                del.type = 'button';
                del.textContent = '🗑';
                del.title = '删除文件夹';
                del.setAttribute('aria-label', '删除文件夹 ' + dir.name);
                del.addEventListener('click', (e) => {
                    e.stopPropagation();
                    deleteFolder(dir);
                });

                dirElement.appendChild(icon);
                dirElement.appendChild(name);
                dirElement.appendChild(del);

                const open = () => navigateTo(dir.path);
                dirElement.addEventListener('click', open);
                dirElement.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') open();
                });

                gallery.appendChild(dirElement);
            });

            // 渲染文件
			files.forEach(file => {
				const fileElement = document.createElement('div');
				fileElement.className = 'item file';
				fileElement.dataset.key = file.key;
				fileElement.tabIndex = 0;

				const checkbox = document.createElement('div');
				checkbox.className = 'checkbox';
				checkbox.setAttribute('role', 'checkbox');
				checkbox.setAttribute('aria-checked', 'false');
				checkbox.setAttribute('aria-label', '选择 ' + file.name);
				checkbox.tabIndex = 0;
				checkbox.addEventListener('click', (e) => {
					e.stopPropagation();
					toggleFileSelection(fileElement, file.key, checkbox);
				});
				checkbox.addEventListener('keydown', (e) => {
					if (e.key === ' ' || e.key === 'Spacebar') {
						e.preventDefault();
						e.stopPropagation();
						toggleFileSelection(fileElement, file.key, checkbox);
					}
				});
				fileElement.appendChild(checkbox);

				if (file.name === '.null') {
					fileElement.classList.add('directory');
					const icon = document.createElement('div');
					icon.className = 'directory-icon';
					icon.textContent = '📄';
					const info = document.createElement('div');
					info.className = 'file-info';
					const nameDiv = document.createElement('div');
					nameDiv.className = 'file-name';
					nameDiv.textContent = 'NULL';
					info.appendChild(nameDiv);
					fileElement.appendChild(icon);
					fileElement.appendChild(info);
				} else {
					const img = document.createElement('img');
					img.src = file.url;
					img.alt = file.name;
					img.className = 'file-image';
					img.loading = 'lazy';
					img.decoding = 'async';

					const actions = document.createElement('div');
					actions.className = 'file-actions';
					actions.appendChild(actionBtn('🔗', '复制直链', () => copyText(file.url, null)));
					actions.appendChild(actionBtn('⬇', '下载', () => downloadFile(file)));
					actions.appendChild(actionBtn('✏', '重命名/移动', () => openRenameModal(file)));

					const info = document.createElement('div');
					info.className = 'file-info';
					const nameDiv = document.createElement('div');
					nameDiv.className = 'file-name';
					nameDiv.textContent = file.name;
					nameDiv.title = file.name;
					const sizeDiv = document.createElement('div');
					sizeDiv.className = 'file-size';
					sizeDiv.textContent = formatFileSize(file.size);
					info.appendChild(nameDiv);
					info.appendChild(sizeDiv);

					fileElement.appendChild(img);
					fileElement.appendChild(actions);
					fileElement.appendChild(info);

					// 点击图片 = 打开大图预览（选中只通过左上角 checkbox / 空格键）
					const openLb = () => openLightbox(file.key);
					fileElement.addEventListener('click', openLb);
					fileElement.addEventListener('keydown', (e) => {
						if (e.key === 'Enter') openLb();
						if (e.key === ' ' || e.key === 'Spacebar') {
							e.preventDefault();
							toggleFileSelection(fileElement, file.key, checkbox);
						}
					});
				}

				// 恢复跨页选中状态（loadMore 追加加载时保留勾选）
				if (selectedFiles.indexOf(file.key) !== -1) {
					fileElement.classList.add('selected');
					checkbox.setAttribute('aria-checked', 'true');
				}

				gallery.appendChild(fileElement);
			});

            // 如果没有内容，显示空状态
            if (directories.length === 0 && files.length === 0) {
                const emptyState = document.createElement('div');
                emptyState.className = 'empty-state';
                emptyState.textContent = '当前文件夹为空';
                gallery.appendChild(emptyState);
            }

            // 显示或隐藏全选控件
            document.querySelector('.select-all-container').style.display = files.length > 0 ? 'flex' : 'none';
        }

        // 切换文件选择状态
        function toggleFileSelection(element, key, checkboxEl) {
            const index = selectedFiles.indexOf(key);
            const checkbox = checkboxEl || element.querySelector('.checkbox');

            if (index === -1) {
                selectedFiles.push(key);
                element.classList.add('selected');
                if (checkbox) checkbox.setAttribute('aria-checked', 'true');
            } else {
                selectedFiles.splice(index, 1);
                element.classList.remove('selected');
                if (checkbox) checkbox.setAttribute('aria-checked', 'false');
            }

            updateDeleteButton();
            updateSelectAllCheckbox();
        }

        // ============ Lightbox 大图预览 ============
        let lbFiles = [];
        let lbIndex = -1;

        function currentLightboxFile() {
            return (lbIndex >= 0 && lbIndex < lbFiles.length) ? lbFiles[lbIndex] : null;
        }

        function openLightbox(key) {
            lbFiles = allFiles.filter(f => f.name !== '.null');
            lbIndex = lbFiles.findIndex(f => f.key === key);
            if (lbIndex === -1) return;
            renderLightbox();
            const lb = document.getElementById('lightbox');
            lb.classList.add('show');
            lb.setAttribute('aria-hidden', 'false');
        }

        function closeLightbox() {
            const lb = document.getElementById('lightbox');
            if (!lb.classList.contains('show')) return;
            lb.classList.remove('show');
            lb.setAttribute('aria-hidden', 'true');
            lbIndex = -1;
        }

        function stepLightbox(delta) {
            if (lbFiles.length === 0) return;
            lbIndex = (lbIndex + delta + lbFiles.length) % lbFiles.length;
            renderLightbox();
        }

        function renderLightbox() {
            const file = currentLightboxFile();
            if (!file) return;
            const img = document.getElementById('lbImg');
            img.src = file.url;
            img.alt = file.name;
            const info = document.getElementById('lbInfo');
            const uploadedText = file.uploaded ? ' · ' + new Date(file.uploaded).toLocaleString() : '';
            info.textContent = file.name + ' · ' + formatFileSize(file.size) + uploadedText;
        }

        // ============ 外链格式与复制 ============
        function formatLinkText(url, fmt) {
            if (fmt === 'md') return '![' + 'img' + '](' + url + ')';
            if (fmt === 'html') return '<img src="' + url + '" />';
            if (fmt === 'bbcode') return '[img]' + url + '[/img]';
            return url;
        }

        function copyText(text, btn) {
            const done = () => {
                if (btn) {
                    const original = btn.textContent;
                    btn.textContent = '已复制';
                    setTimeout(() => { btn.textContent = original; }, 1500);
                }
            };
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
            } else {
                fallbackCopy(text, done);
            }
        }

        function fallbackCopy(text, done) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch (e) {}
            document.body.removeChild(ta);
            done();
        }

        // 下载（blob 方式保证 download 文件名生效）
        async function downloadFile(file) {
            try {
                showLoading(true);
                const resp = await fetch(file.url);
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                const blob = await resp.blob();
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = file.name;
                document.body.appendChild(a);
                a.click();
                a.remove();
                setTimeout(() => URL.revokeObjectURL(a.href), 4000);
            } catch (e) {
                showNotification('下载失败，请重试', true);
            } finally {
                showLoading(false);
            }
        }

        // 删除文件夹（二次确认：confirm + 输入文件夹名）
        async function deleteFolder(dir) {
            const sure = confirm('确定删除文件夹「' + dir.name + '」吗？\\n文件夹内的所有内容（包括子文件夹与图片）将被永久删除！');
            if (!sure) return;
            const typed = prompt('此操作不可恢复！\\n请输入文件夹名称 ' + dir.name + ' 以确认：');
            if (typed !== dir.name) {
                showNotification('名称不匹配，已取消删除', true);
                return;
            }
            showLoading(true);
            try {
                const response = await fetch('/api/delete-folder', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: dir.path })
                });
                const data = await response.json();
                if (data.success) {
                    showNotification(data.message || '文件夹已删除');
                    await loadGallery();
                } else {
                    showNotification(data.message || '删除失败，请重试', true);
                }
            } catch (error) {
                console.error('删除文件夹失败:', error);
                showNotification('删除失败，请重试', true);
            } finally {
                showLoading(false);
            }
        }

        // 切换页码（旧分页系统已移除：后端为游标"加载更多"模式）

        // 切换文件选择状态
        function toggleFileSelection(element, key) {
            const index = selectedFiles.indexOf(key);

            if (index === -1) {
                // 添加到选中列表
                selectedFiles.push(key);
                element.classList.add('selected');
            } else {
                // 从选中列表中移除
                selectedFiles.splice(index, 1);
                element.classList.remove('selected');
            }

            // 更新删除按钮状态
            updateDeleteButton();

            // 更新全选状态
            updateSelectAllCheckbox();
        }

        // 全选/取消全选
        function toggleSelectAll() {
            const selectAllCheckbox = document.getElementById('selectAllCheckbox');
            const isChecked = selectAllCheckbox.checked;

            // 获取所有文件元素
            const fileElements = document.querySelectorAll('.file');

            if (isChecked) {
                // 全选
                selectedFiles = [];
                fileElements.forEach(fileElement => {
                    const key = fileElement.dataset.key;
                    if (!selectedFiles.includes(key)) {
                        selectedFiles.push(key);
                        fileElement.classList.add('selected');
                    }
                });
            } else {
                // 取消全选
                selectedFiles = [];
                fileElements.forEach(fileElement => {
                    fileElement.classList.remove('selected');
                });
            }

            // 更新删除按钮状态
            updateDeleteButton();
        }

        // 更新全选复选框状态
        function updateSelectAllCheckbox() {
            const selectAllCheckbox = document.getElementById('selectAllCheckbox');
            const fileElements = document.querySelectorAll('.file');

            // 如果没有文件，则禁用全选
            if (fileElements.length === 0) {
                selectAllCheckbox.checked = false;
                return;
            }

            // 检查是否所有文件都被选中
            selectAllCheckbox.checked = selectedFiles.length === fileElements.length;
        }

        // 更新删除按钮状态
        function updateDeleteButton() {
            const deleteBtn = document.getElementById('deleteBtn');
            deleteBtn.disabled = selectedFiles.length === 0;
        }

        // ============ 重命名 / 移动 ============
        let renameSourceKey = null;

        function openRenameModal(key) {
            const file = allFiles.find(f => f.key === key);
            if (!file) return;
            renameSourceKey = key;
            // 预填：名称=当前文件名；目标文件夹=当前所在文件夹
            const nameInput = document.getElementById('renameName');
            const folderInput = document.getElementById('renameFolder');
            nameInput.value = file.name;
            folderInput.value = currentPath.replace(/\\/$/, '');
            showModal('renameModal');
            nameInput.focus();
            nameInput.select();
        }

        async function confirmRename() {
            if (!renameSourceKey) return;
            const name = document.getElementById('renameName').value.trim();
            const folder = normalizeClientPath(document.getElementById('renameFolder').value.trim()).replace(/\\/$/, '');
            const sourceFile = allFiles.find(f => f.key === renameSourceKey);
            if (!sourceFile) { showNotification('文件不存在', true); return; }

            // 客户端预检：服务端会再验一次
            const nameInvalid = !name || /[\\/:*?"<>|]/.test(name);
            if (nameInvalid) { showNotification('文件名含非法字符', true); return; }

            const sourceName = sourceFile.name;
            const targetKey = (folder ? folder + '/' : '') + name;

            if (targetKey === renameSourceKey) {
                showNotification('新名称与原名称相同', true);
                return;
            }

            showLoading(true);
            try {
                const response = await fetch('/api/rename', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sourceKey: renameSourceKey, targetKey: targetKey })
                });
                const data = await response.json();
                if (data.success) {
                    showNotification(data.message || '重命名成功');
                    document.getElementById('renameModal').style.display = 'none';
                    await loadGallery();
                } else {
                    showNotification(data.message || '重命名失败', true);
                }
            } catch (error) {
                console.error('重命名失败:', error);
                showNotification('重命名失败，请重试', true);
            } finally {
                showLoading(false);
                renameSourceKey = null;
            }
        }

        // ============ 存储用量统计 ============
        async function openStats() {
            showModal('statsModal');
            const content = document.getElementById('statsContent');
            content.textContent = '加载中…';
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                if (!data.success) throw new Error(data.message || '统计失败');
                content.innerHTML = '';

                const row = document.createElement('div');
                row.className = 'stats-row';
                const mk = (value, label) => {
                    const cell = document.createElement('div');
                    cell.style.textAlign = 'center';
                    const v = document.createElement('div');
                    v.className = 'stats-big';
                    v.textContent = value;
                    const l = document.createElement('div');
                    l.className = 'stats-label';
                    l.textContent = label;
                    cell.appendChild(v);
                    cell.appendChild(l);
                    return cell;
                };
                row.appendChild(mk(String(data.totalFiles), '总文件数'));
                row.appendChild(mk(formatFileSize(data.totalBytes), '总体积'));
                row.appendChild(mk(String(data.last7Days), '近 7 日上传'));
                content.appendChild(row);

                if (data.scannedTruncated) {
                    const warn = document.createElement('p');
                    warn.className = 'stats-label';
                    warn.style.textAlign = 'center';
                    warn.textContent = '文件较多，仅统计前 5000 项';
                    content.appendChild(warn);
                }

                if (data.folders && data.folders.length > 0) {
                    const table = document.createElement('table');
                    table.className = 'stats-table';
                    const thead = document.createElement('thead');
                    const hr = document.createElement('tr');
                    ['文件夹', '文件数', '体积'].forEach(t => {
                        const th = document.createElement('th');
                        th.textContent = t;
                        hr.appendChild(th);
                    });
                    thead.appendChild(hr);
                    table.appendChild(thead);
                    const tbody = document.createElement('tbody');
                    data.folders.forEach(folder => {
                        const tr = document.createElement('tr');
                        const tdName = document.createElement('td');
                        tdName.textContent = folder.name;
                        const tdCount = document.createElement('td');
                        tdCount.textContent = String(folder.files);
                        const tdSize = document.createElement('td');
                        tdSize.textContent = formatFileSize(folder.bytes);
                        tr.appendChild(tdName);
                        tr.appendChild(tdCount);
                        tr.appendChild(tdSize);
                        tbody.appendChild(tr);
                    });
                    table.appendChild(tbody);
                    content.appendChild(table);
                }

                const cached = document.createElement('p');
                cached.className = 'stats-label';
                cached.style.textAlign = 'center';
                cached.style.marginTop = '10px';
                cached.textContent = '统计缓存 1 小时（上传/删除后自动刷新）';
                content.appendChild(cached);
            } catch (error) {
                content.textContent = '统计加载失败：' + (error.message || '请重试');
            }
        }

        // 显示模态框
        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) modal.style.display = 'flex';
        }

        // ============ 回收站 ============
        let trashMode = false;

        async function openTrash() {
            trashMode = true;
            document.getElementById('trashBtn').classList.add('btn-active');
            document.getElementById('newFolderBtn').disabled = true;
            document.getElementById('deleteBtn').disabled = true;
            document.getElementById('deleteBtn').classList.add('hidden');
            await loadTrash();
        }

        function exitTrash() {
            if (!trashMode) return;
            trashMode = false;
            document.getElementById('trashBtn').classList.remove('btn-active');
            document.getElementById('newFolderBtn').disabled = false;
            document.getElementById('deleteBtn').classList.remove('hidden');
            selectedFiles = [];
            document.getElementById('gallery').innerHTML = '';
            document.getElementById('breadcrumb').innerHTML = '<a href="/gallery" data-path="">首页</a>';
            updateUploadLink();
            loadGallery();
        }

        function renderTrash(files) {
            const gallery = document.getElementById('gallery');
            gallery.innerHTML = '';
            gallery.classList.add('trash-view');
            gallery.classList.remove('list-view');

            const breadcrumb = document.getElementById('breadcrumb');
            breadcrumb.innerHTML = '';
            const backLink = document.createElement('a');
            backLink.href = '#';
            backLink.textContent = '← 返回图库';
            backLink.addEventListener('click', (e) => {
                e.preventDefault();
                exitTrash();
            });
            const sep = document.createElement('span');
            sep.textContent = ' / 回收站';
            breadcrumb.appendChild(backLink);
            breadcrumb.appendChild(sep);

            // 工具条
            const toolbar = document.createElement('div');
            toolbar.className = 'trash-toolbar';
            const info = document.createElement('span');
            info.textContent = files.length + ' 个文件（保留 30 天，到期需配置 Cron 自动清理）';
            const spacer = document.createElement('span');
            spacer.className = 'spacer';
            const emptyBtn = document.createElement('button');
            emptyBtn.className = 'btn btn-danger';
            emptyBtn.type = 'button';
            emptyBtn.textContent = '清空回收站';
            emptyBtn.addEventListener('click', () => {
                if (files.length === 0) { showNotification('回收站已是空的'); return; }
                showModal('purgeModal');
            });
            toolbar.appendChild(info);
            toolbar.appendChild(spacer);
            toolbar.appendChild(emptyBtn);
            gallery.appendChild(toolbar);

            if (files.length === 0) {
                const empty = document.createElement('p');
                empty.style.textAlign = 'center';
                empty.style.color = '#86868b';
                empty.textContent = '回收站是空的';
                gallery.appendChild(empty);
                return;
            }

            files.forEach(file => {
                const row = document.createElement('div');
                row.className = 'trash-row';

                const name = document.createElement('span');
                name.className = 'trash-name';
                name.textContent = file.key;
                name.title = file.key;

                const date = document.createElement('span');
                date.className = 'trash-date';
                date.textContent = '删除于 ' + formatDateTime(file.uploaded);

                const restoreBtn = document.createElement('button');
                restoreBtn.className = 'btn-restore';
                restoreBtn.type = 'button';
                restoreBtn.textContent = '恢复';
                restoreBtn.addEventListener('click', () => trashAction('/api/trash/restore', [file.trashKey], restoreBtn));

                const purgeBtn = document.createElement('button');
                purgeBtn.className = 'btn-purge-one';
                purgeBtn.type = 'button';
                purgeBtn.textContent = '彻底删除';
                purgeBtn.addEventListener('click', () => {
                    if (confirm('彻底删除 ' + file.key + ' ？\\n此操作不可撤销。')) {
                        trashAction('/api/trash/purge', [file.trashKey], purgeBtn);
                    }
                });

                row.appendChild(name);
                row.appendChild(date);
                row.appendChild(restoreBtn);
                row.appendChild(purgeBtn);
                gallery.appendChild(row);
            });
        }

        async function loadTrash() {
            showLoading(true);
            try {
                const response = await fetch('/api/trash');
                const data = await response.json();
                if (data.success) {
                    renderTrash(data.files);
                } else {
                    showNotification(data.message || '回收站读取失败', true);
                }
            } catch (error) {
                showNotification('回收站读取失败', true);
            } finally {
                showLoading(false);
            }
        }

        async function trashAction(url, keys, btn) {
            if (btn) { btn.disabled = true; btn.textContent = '处理中…'; }
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ keys: keys })
                });
                const data = await response.json();
                showNotification(data.message || (data.success ? '操作成功' : '操作失败'), !data.success);
            } catch (error) {
                showNotification('操作失败，请重试', true);
            }
            await loadTrash();
        }

        async function purgeAllTrash() {
            const btn = document.getElementById('purgeConfirmBtn');
            btn.disabled = true;
            try {
                const response = await fetch('/api/trash/purge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                const data = await response.json();
                showNotification(data.message || (data.success ? '已清空' : '操作失败'), !data.success);
                document.getElementById('purgeModal').style.display = 'none';
            } catch (error) {
                showNotification('操作失败，请重试', true);
            } finally {
                btn.disabled = false;
            }
            await loadTrash();
        }

        function formatDateTime(iso) {
            try {
                const d = new Date(iso);
                const p = (n) => String(n).padStart(2, '0');
                return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
            } catch (e) {
                return '';
            }
        }

        // 删除选中的文件（展示部分失败明细）
        async function deleteSelectedFiles() {
            if (selectedFiles.length === 0) return;

            if (!confirm('确定要删除选中的 ' + selectedFiles.length + ' 个文件吗？')) {
                return;
            }

            showLoading(true);

            try {
                const response = await fetch('/api/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'keys': selectedFiles
                    })
                });

                const data = await response.json();

                if (data.success) {
                    const failed = data.failed || [];
                    if (failed.length > 0) {
                        showNotification('已删除 ' + (data.deletedCount || 0) + ' 个，' + failed.length + ' 个失败', true);
                    } else {
                        showNotification('删除成功');
                    }
                    await loadGallery(); // 重新加载画廊
                } else {
                    showNotification(data.message || '删除失败，请重试', true);
                }
            } catch (error) {
                console.error('删除失败:', error);
                showNotification('删除失败，请重试', true);
            } finally {
                showLoading(false);
            }
        }

        // 创建新文件夹
        async function createFolder() {
            const folderNameInput = document.getElementById('folderName');
            const folderName = folderNameInput.value.trim();

            if (!folderName) {
                alert('请输入文件夹名称');
                return;
            }

            showLoading(true);

            try {
                const path = currentPath ? currentPath + folderName + '/' : folderName + '/';

                const response = await fetch('/api/create-folder', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ path })
                });

                const data = await response.json();

                if (data.success) {
                    showNotification('文件夹创建成功');
                    document.getElementById('folderModal').style.display = 'none';
                    folderNameInput.value = '';
                    await loadGallery(); // 重新加载画廊
                } else {
                    showNotification('文件夹创建失败，请重试', true);
                }
            } catch (error) {
                console.error('文件夹创建失败:', error);
                showNotification('文件夹创建失败，请重试', true);
            } finally {
                showLoading(false);
            }
        }

        // 显示模态框
        function showModal(id) {
            const modal = document.getElementById(id);
            modal.style.display = 'flex';

            // 如果是文件夹模态框，聚焦输入框
            if (id === 'folderModal') {
                setTimeout(() => {
                    document.getElementById('folderName').focus();
                }, 100);
            }
        }

        // 显示/隐藏加载指示器
        function showLoading(show) {
            const loading = document.getElementById('loading');
            loading.style.display = show ? 'flex' : 'none';
        }

        // 显示通知
        function showNotification(message, isError = false) {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = isError ? 'notification error' : 'notification';

            // 显示通知
            setTimeout(() => {
                notification.classList.add('show');
            }, 10);

            // 3秒后隐藏
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }

        // 格式化文件大小
        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
    </script>
</body>
</html>
    `;

	return new Response(html, {
		headers: {'Content-Type': 'text/html; charset=utf-8'}
	});
}

async function handleWebUpload(request, env, bucket, cfg) {
	try {
		// Parse the form data
		const formData = await request.formData();
		const file = formData.get('file');
		const rawPath = String(formData.get('path') || '');

		if (!file || typeof file === 'string') {
			return jsonError(400, 'NO_FILE', '未收到文件');
		}

		// 服务端大小上限（压缩已前置到浏览器端，见上传页 JS）
		if (file.size > UPLOAD_MAX_BYTES) {
			return jsonError(413, 'FILE_TOO_LARGE', `文件超过大小上限（${Math.floor(UPLOAD_MAX_BYTES / 1024 / 1024)}MB）`);
		}

		// 上传路径规范化（防 ../ 与非法字符）
		const normalizedPath = sanitizeFolderPath(rawPath);
		if (normalizedPath === null) {
			return jsonError(400, 'INVALID_PATH', '路径格式无效：仅允许中文、字母、数字、下划线、短横线');
		}
		// 保留前缀：不允许上传到回收站
		if (normalizedPath === '__trash__' || normalizedPath.startsWith('__trash__/')) {
			return jsonError(400, 'RESERVED_PATH', '该路径为系统保留（回收站）');
		}

		// Process file data
		const fileBuffer = await file.arrayBuffer();
		const uint8Array = new Uint8Array(fileBuffer);

		// Detect file type by magic number
		const detectedType = detectImageType(uint8Array);
		if (!detectedType) {
			return jsonError(400, 'UNSUPPORTED_TYPE', '仅支持 JPG / PNG / GIF / WebP / BMP 格式');
		}

		// Generate file name with date prefix and UUID
		const date = new Date();
		const formattedDate = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, '0')}${String(date.getDate()).padStart(2, '0')}`;
		const shortUUID = crypto.randomUUID().split('-')[0];

		// Build file key with folder prefix if provided
		let key = `${formattedDate}_${shortUUID}.${detectedType.ext}`;
		if (normalizedPath) {
			key = `${normalizedPath}/${key}`;
		}

		// Upload to R2（不做服务端格式转换：>500KB 的压缩已由浏览器完成，见 P0-1 方案 A）
		await bucket.put(key, fileBuffer, {
			httpMetadata: {
				contentType: detectedType.mime
			}
		});
		await invalidateStatsCache(env);

		// Generate URLs for response
		const imageUrl = `${cfg.baseUrl}/${key}`;

		return jsonOk({
			url: imageUrl,
			markdown: `![img](${imageUrl})`,
			key: key
		});

	} catch (error) {
		console.error('Upload failed:', error);
		return jsonError(500, 'UPLOAD_FAILED', '上传失败，请稍后再试');
	}
}

async function handleListFiles(request, bucket, baseUrl) {
	const {searchParams} = new URL(request.url);
	let limit = parseInt(searchParams.get('limit')) || 20;
	limit = Math.min(Math.max(limit, 1), 1000); // 钳制，防滥用
	const folderPrefix = searchParams.get('prefix') || '';
	const opaqueCursor = searchParams.get('cursor') || '';

	// 解析游标：base64url(JSON {d:'YYYYMMDD', r2c?})，d=下一个待扫描日期桶，r2c=该日内的 R2 续读游标
	let startDay = todayStr();
	let resumeR2Cursor;
	if (opaqueCursor) {
		try {
			const parsed = JSON.parse(atob(opaqueCursor.replace(/-/g, '+').replace(/_/g, '/')));
			if (parsed && /^\d{8}$/.test(parsed.d)) {
				startDay = parsed.d;
				if (typeof parsed.r2c === 'string') resumeR2Cursor = parsed.r2c;
			}
		} catch (e) {
			// 无效游标按首页处理
		}
	}

	// 1) 目录列表（1 次子请求，最多取 1000 个子文件夹；排除回收站目录）
	const dirsResult = await bucket.list({prefix: folderPrefix, delimiter: '/', limit: 1000});
	const directories = (dirsResult.delimitedPrefixes || [])
		.filter(delimitedPrefix => delimitedPrefix !== TRASH_PREFIX)
		.map(delimitedPrefix => {
			const name = delimitedPrefix.substring(folderPrefix.length).replace(/\/$/, '');
			return {
				name: name,
				path: delimitedPrefix,
				type: 'directory'
			};
		});

	// 2) 按天倒序扫描文件（排序修复：R2 list 仅字典序正向游标，
	//    利用 key 自带 YYYYMMDD 日期前缀做按天分桶；整天原子返回，杜绝丢页/重复）
	const MAX_SCAN_DAYS = 30;      // 单次请求最多向前扫描的天数
	const MAX_COLLECTED = 2000;    // 单次响应文件数上限（防超大页）
	const MAX_ALL_LIMIT = 5000;    // all=1 聚合模式总上限
	const collected = [];
	// all=1：聚合模式 — 除当前目录外，把每个子文件夹的内容也按天倒序并入列表
	// （修复：TG 上传落在"图片/"子文件夹后，根目录图库只显示根下文件，用户以为图片丢了）
	const wantAll = searchParams.get('all') === '1';
	if (wantAll) {
		// all=1 独立路径：当前层文件（delimiter 模式自带）+ 每个子文件夹平铺 list，一次拿全，内存排序。
		// 不走按天分桶/游标翻页（天数多时子请求爆炸 → 超时；跨文件夹翻页语义混乱）。
		// 上限 MAX_COLLECTED（2000）保护；超大图库未来再分片。
		const collected = [];
		for (const object of dirsResult.objects) {
			if (object.key.endsWith('/.null')) continue;
			if (isTrashKey(object.key)) continue;
			collected.push(object);
		}
		for (const dir of (dirsResult.delimitedPrefixes || []).slice(0, 20)) {
			if (dir === TRASH_PREFIX || isTrashKey(dir)) continue;
			let subCursor;
			do {
				const subPage = await bucket.list({prefix: dir, limit: 1000, cursor: subCursor});
				for (const object of subPage.objects) {
					if (object.key.endsWith('/.null')) continue;
					collected.push(object);
				}
				subCursor = subPage.truncated ? subPage.cursor : undefined;
			} while (subCursor && collected.length < MAX_ALL_LIMIT);
		}
		collected.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
		const limited = collected.slice(0, MAX_ALL_LIMIT);
		const formattedFiles = limited.map(object => {
			const name = object.key.substring(folderPrefix.length);
			return {
				name: name,
				key: object.key,
				size: object.size,
				uploaded: object.uploaded,
				type: 'file',
				url: `${baseUrl}/${encodeURIComponent(object.key)}`
			};
		});
		return new Response(JSON.stringify({
			files: formattedFiles,
			prefix: directories,
			cursor: null,
			hasMore: false,
			total: collected.length
		}), {headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}});
	}
	let day = startDay;
	let r2Cursor = resumeR2Cursor;
	let scannedDays = 0;
	let stopReason = 'floor';

// 3) 扫满 30 天窗口仍不足一页：用"最旧 key 探针"决定回跳或收尾
	//    （否则稀疏图库/很久没上传的用户会看到空列表）
	let legacyMode = false;
	let jumpTruncated = false;
	if (stopReason === 'floor') {
		// 探针取最旧的非 .null key（.null 是文件夹占位标记；__trash__/ 是回收站，均不代表图库内容）
		let firstKey = null;
		let probeCursor;
		do {
			const probe = await bucket.list({prefix: folderPrefix, limit: 10, cursor: probeCursor});
			for (const object of probe.objects) {
				if (!object.key.endsWith('/.null') && !object.key.endsWith('.null') && !isTrashKey(object.key)) {
					firstKey = object.key;
					break;
				}
			}
			probeCursor = probe.truncated ? probe.cursor : undefined;
		} while (!firstKey && probeCursor);
		const rel = firstKey ? firstKey.substring(folderPrefix.length) : '';
		const m = rel.match(/^(\d{8})_/);
		if (m && parseInt(m[1], 10) < parseInt(day, 10)) {
			// 存在更旧的日期桶：直接跳到最旧的一天扫描（一次请求最多跳一次）
			day = m[1];
			let jumpCursor;
			do {
				const page = await bucket.list({prefix: folderPrefix + day, limit: 1000, cursor: jumpCursor});
				for (const object of page.objects) {
					if (object.key.endsWith('/.null')) continue;
					collected.push(object);
				}
				jumpCursor = page.truncated ? page.cursor : undefined;
			} while (jumpCursor && collected.length < MAX_COLLECTED);
			jumpTruncated = !!jumpCursor; // 最旧一天太多没扫完
			if (jumpTruncated) {
				// 未扫完：保留日内续读状态，hasMore 走 'limit' 分支
				r2Cursor = jumpCursor;
				stopReason = 'limit';
			} else {
				day = prevDay(day);
			}
		} else if (firstKey && !m) {
			// 不带日期前缀的遗留 key（外部工具直传）：按字典序兜底返回一页
			const page = await bucket.list({prefix: folderPrefix, limit: limit});
			for (const object of page.objects) {
				if (object.key.endsWith('/.null')) continue;
				if (isTrashKey(object.key)) continue;
				collected.push(object);
			}
			legacyMode = true;
		}
	}

	// 桶间已按天倒序；桶内按上传时间降序（双保险 = 全局最新在前）
	collected.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));

	const formattedFiles = collected.map(object => {
		const name = object.key.substring(folderPrefix.length);
		return {
			name: name,
			key: object.key,
			size: object.size,
			uploaded: object.uploaded,
			type: 'file',
			url: `${baseUrl}/${encodeURIComponent(object.key)}`
		};
	});

	// hasMore 判定：
	//   stopReason='limit' → 当前窗口装满（或超大单日未扫完），可能还有更多
	//   stopReason='floor' → 已扫到探针确认的最旧一天并整扫完 → 收尾（遗留兜底页同样收尾）
	const hasMore = stopReason === 'limit';
	let nextCursor = null;
	if (hasMore) {
		const cursorPayload = {d: day};
		if (r2Cursor) cursorPayload.r2c = r2Cursor;
		nextCursor = btoa(JSON.stringify(cursorPayload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	return new Response(JSON.stringify({
		files: formattedFiles,
		prefix: directories,
		cursor: nextCursor,
		hasMore: hasMore
	}), {
		headers: {'Content-Type': 'application/json'}
	});
}

function todayStr() {
	const d = new Date();
	return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
}

function prevDay(dayStr) {
	const y = parseInt(dayStr.slice(0, 4), 10);
	const m = parseInt(dayStr.slice(4, 6), 10);
	const d = parseInt(dayStr.slice(6, 8), 10);
	const date = new Date(Date.UTC(y, m - 1, d - 1));
	return `${date.getUTCFullYear()}${String(date.getUTCMonth() + 1).padStart(2, '0')}${String(date.getUTCDate()).padStart(2, '0')}`;
}

async function handleDeleteFiles(request, env, bucket) {
	try {
		const body = await request.json();
		let keys = body.keys;
		if (!keys || !Array.isArray(keys) || keys.length === 0 || keys.some(k => typeof k !== 'string')) {
			return jsonError(400, 'INVALID_KEYS', '未提供有效的删除目标');
		}
		// 回收站内的对象不允许再次"删除"（请用 /api/trash/purge 彻底删除）
		const invalid = keys.filter(k => isTrashKey(k));
		if (invalid.length > 0) {
			return jsonError(400, 'TRASH_KEY_FORBIDDEN', '回收站对象请通过"彻底删除"操作移除');
		}

		const permanent = body.permanent === true;
		if (permanent) {
			return await purgeKeys(env, bucket, keys, '成功彻底删除');
		}

		// 软删除：copy 到回收站（保留原路径），成功后删除原件；copy 失败的对象保留不删
		const movedIn = [];
		const moveFailed = [];
		for (const key of keys) {
			try {
				const head = await bucket.head(key);
				if (!head) {
					// 对象不存在：按 R2 语义视为已删除（与旧版批量删除行为一致）
					movedIn.push(key);
					continue;
				}
				await bucket.copy(TRASH_PREFIX + key, key);
				const verify = await bucket.head(TRASH_PREFIX + key);
				if (!verify) throw new Error('copy verify failed');
				movedIn.push(key);
			} catch (e) {
				moveFailed.push({key, message: String((e && e.message) || 'move to trash failed')});
			}
		}

		// 批量删除已入回收站的原件（R2 单次 ≤1000）
		const deleted = [];
		const failed = [...moveFailed];
		for (let i = 0; i < movedIn.length; i += 1000) {
			const chunk = movedIn.slice(i, i + 1000);
			try {
				await bucket.delete(chunk);
				deleted.push(...chunk);
			} catch (chunkError) {
				const results = await Promise.allSettled(chunk.map(key => bucket.delete(key)));
				results.forEach((r, idx) => {
					if (r.status === 'fulfilled') {
						deleted.push(chunk[idx]);
					} else {
						failed.push({key: chunk[idx], message: String((r.reason && r.reason.message) || 'delete failed')});
					}
				});
			}
		}

		// 删除失败的原件：撤回回收站副本，避免产生重复占用
		await Promise.allSettled(
			failed.map(f => bucket.delete(TRASH_PREFIX + f.key))
		);

		const success = deleted.length > 0;
		if (success) await invalidateStatsCache(env);
		return new Response(JSON.stringify({
			success: success,
			deleted: deleted,
			deletedCount: deleted.length,
			failed: failed,
			softDeleted: true,
			message: failed.length === 0
				? `已移入回收站 ${deleted.length} 个文件`
				: `已移入回收站 ${deleted.length} 个文件，${failed.length} 个失败`
		}), {
			status: success ? 200 : 500,
			headers: {'Content-Type': 'application/json'}
		});
	} catch (error) {
		console.error('Delete files error:', error);
		return jsonError(500, 'DELETE_FAILED', '删除失败');
	}
}

// 彻底删除一组 key（回收站清空/单项彻底删除共用）
async function purgeKeys(env, bucket, keys, okMessage) {
	const deleted = [];
	const failed = [];
	for (let i = 0; i < keys.length; i += 1000) {
		const chunk = keys.slice(i, i + 1000);
		try {
			await bucket.delete(chunk);
			deleted.push(...chunk);
		} catch (chunkError) {
			const results = await Promise.allSettled(chunk.map(key => bucket.delete(key)));
			results.forEach((r, idx) => {
				if (r.status === 'fulfilled') {
					deleted.push(chunk[idx]);
				} else {
					failed.push({key: chunk[idx], message: String((r.reason && r.reason.message) || 'delete failed')});
				}
			});
		}
	}
	const success = deleted.length > 0;
	if (success) await invalidateStatsCache(env);
	return new Response(JSON.stringify({
		success: success,
		deleted: deleted,
		deletedCount: deleted.length,
		failed: failed,
		message: failed.length === 0
			? `${okMessage} ${deleted.length} 个文件`
			: `${okMessage} ${deleted.length} 个文件，${failed.length} 个失败`
	}), {
		status: success ? 200 : 500,
		headers: {'Content-Type': 'application/json'}
	});
}

// 列回收站（返回原名 + 删除时间）
async function handleTrashList(request, env, bucket) {
	try {
		const files = [];
		let r2Cursor;
		let truncatedOuter = false;
		do {
			const page = await bucket.list({prefix: TRASH_PREFIX, limit: 1000, cursor: r2Cursor});
			for (const object of page.objects) {
				if (object.key.endsWith('/.null')) continue;
				files.push({
					key: object.key.slice(TRASH_PREFIX.length),
					trashKey: object.key,
					size: object.size || 0,
					uploaded: object.uploaded
				});
			}
			r2Cursor = page.truncated ? page.cursor : undefined;
			if (files.length >= 2000) truncatedOuter = true;
		} while (r2Cursor && !truncatedOuter);

		return jsonOk({files, hasMore: truncatedOuter});
	} catch (error) {
		console.error('Trash list error:', error);
		return jsonError(500, 'TRASH_LIST_FAILED', '回收站读取失败');
	}
}

// 从回收站恢复（copy 回原位 + 删除回收站副本；同名对象会被覆盖）
async function handleTrashRestore(request, env, bucket) {
	try {
		const body = await request.json();
		const keys = body.keys;
		if (!keys || !Array.isArray(keys) || keys.length === 0 || keys.some(k => typeof k !== 'string')) {
			return jsonError(400, 'INVALID_KEYS', '未提供有效的恢复目标');
		}

		const restored = [];
		const failed = [];
		for (const trashKey of keys) {
			try {
				if (!isTrashKey(trashKey)) {
					failed.push({key: trashKey, message: '不是回收站对象'});
					continue;
				}
				const originalKey = trashKey.slice(TRASH_PREFIX.length);
				if (!originalKey) {
					failed.push({key: trashKey, message: '原路径为空'});
					continue;
				}
				await bucket.copy(originalKey, trashKey);
				const verify = await bucket.head(originalKey);
				if (!verify) throw new Error('restore verify failed');
				await bucket.delete(trashKey);
				restored.push(originalKey);
			} catch (e) {
				failed.push({key: trashKey, message: String((e && e.message) || 'restore failed')});
			}
		}

		const success = restored.length > 0;
		if (success) await invalidateStatsCache(env);
		return new Response(JSON.stringify({
			success: success,
			restored,
			restoredCount: restored.length,
			failed,
			message: failed.length === 0
				? `已恢复 ${restored.length} 个文件`
				: `已恢复 ${restored.length} 个文件，${failed.length} 个失败`
		}), {
			status: success ? 200 : 500,
			headers: {'Content-Type': 'application/json'}
		});
	} catch (error) {
		console.error('Trash restore error:', error);
		return jsonError(500, 'TRASH_RESTORE_FAILED', '恢复失败');
	}
}

// 彻底删除：keys 缺省 = 清空整个回收站（上限 5000）
async function handleTrashPurge(request, env, bucket) {
	try {
		const body = await request.json().catch(() => ({}));
		let keys = Array.isArray(body.keys) ? body.keys.filter(k => typeof k === 'string' && isTrashKey(k)) : null;

		if (!keys) {
			keys = [];
			let r2Cursor;
			do {
				const page = await bucket.list({prefix: TRASH_PREFIX, limit: 1000, cursor: r2Cursor});
				for (const object of page.objects) {
					keys.push(object.key);
				}
				r2Cursor = page.truncated ? page.cursor : undefined;
				if (keys.length >= 5000) break;
			} while (r2Cursor);
		}

		if (keys.length === 0) {
			return jsonOk({message: '回收站已是空的', deletedCount: 0});
		}
		return await purgeKeys(env, bucket, keys, '已彻底删除');
	} catch (error) {
		console.error('Trash purge error:', error);
		return jsonError(500, 'TRASH_PURGE_FAILED', '彻底删除失败');
	}
}


async function handleCreateFolder(request, bucket) {
	try {
		// Parse the JSON body to get the folder path
		const body = await request.json();
		const normalized = sanitizeFolderPath(String(body.path || ''));

		if (normalized === null) {
			return jsonError(400, 'INVALID_PATH', '文件夹名称无效：仅允许中文、字母、数字、下划线、短横线');
		}
		if (normalized === '') {
			return jsonError(400, 'INVALID_PATH', '文件夹名称不能为空');
		}

		// Ensure the folder path ends with a slash
		const folderPath = `${normalized}/`;

		// Create a .null file to represent the folder (a common practice in S3/R2)
		const nullPath = `${folderPath}.null`;
		await bucket.put(nullPath, new Uint8Array(0), {
			httpMetadata: {
				contentType: 'application/x-directory'
			}
		});

		return jsonOk({
			message: "Folder created successfully",
			path: folderPath
		});
	} catch (error) {
		console.error('Create folder error:', error);
		return jsonError(500, 'CREATE_FOLDER_FAILED', 'Failed to create folder');
	}
}

// 删除文件夹：收集前缀下全部 key 后批量删除（此前 handleDeleteFolder 未定义、路由必 500）
async function handleDeleteFolder(request, env, bucket) {
	try {
		const body = await request.json();
		const normalized = sanitizeFolderPath(String(body.path || ''));
		if (normalized === null || normalized === '') {
			return jsonError(400, 'INVALID_PATH', '文件夹路径无效');
		}
		// 回收站前缀保留：不允许通过"删除文件夹"清空回收站（请用回收站的彻底删除）
		if (normalized === '__trash__' || normalized.startsWith('__trash__/')) {
			return jsonError(400, 'RESERVED_PATH', '该路径为系统保留（回收站），请使用回收站的"清空/彻底删除"操作');
		}
		const folderPrefix = `${normalized}/`;

		// 收集文件夹下全部 key（含子文件夹），设上限防误删超大目录
		const allKeys = [];
		let r2Cursor;
		do {
			const page = await bucket.list({prefix: folderPrefix, limit: 1000, cursor: r2Cursor});
			for (const object of page.objects) {
				allKeys.push(object.key);
			}
			r2Cursor = page.truncated ? page.cursor : undefined;
			if (allKeys.length >= 10000) {
				return jsonError(400, 'TOO_MANY_OBJECTS', '文件夹内容过多（超过 10000 项），为安全起见请分批删除');
			}
		} while (r2Cursor);

		// R2 binding 支持单次最多 1000 key 的批量删除
		for (let i = 0; i < allKeys.length; i += 1000) {
			await bucket.delete(allKeys.slice(i, i + 1000));
		}
		await invalidateStatsCache(env);

		return jsonOk({
			message: `文件夹已删除（共 ${allKeys.length} 项）`,
			deletedCount: allKeys.length
		});
	} catch (error) {
		console.error('Delete folder error:', error);
		return jsonError(500, 'DELETE_FOLDER_FAILED', '删除文件夹失败');
	}
}



// 重命名/移动：R2 无原生 rename，用 copy + delete 模拟（copy 保留元数据）
async function handleRename(request, env, bucket) {
	try {
		const body = await request.json();
		const sourceKey = String(body.sourceKey || '');
		const targetKey = String(body.targetKey || '');

		if (!sourceKey || !targetKey) {
			return jsonError(400, 'MISSING_PARAMS', '缺少 sourceKey 或 targetKey');
		}
		if (sourceKey === targetKey) {
			return jsonError(400, 'SAME_KEY', '新名称与原名称相同');
		}
		// 回收站前缀保留：不允许 rename 进/出回收站
		if (isTrashKey(sourceKey) || isTrashKey(targetKey)) {
			return jsonError(400, 'RESERVED_PATH', '该路径为系统保留（回收站），请使用回收站的恢复功能');
		}

		// 目标 key 校验：目录段 + 文件名分别规范
		const slashIdx = targetKey.lastIndexOf('/');
		const targetDir = slashIdx === -1 ? '' : targetKey.slice(0, slashIdx);
		const targetName = slashIdx === -1 ? targetKey : targetKey.slice(slashIdx + 1);
		const normalizedDir = sanitizeFolderPath(targetDir);
		const normalizedName = sanitizeFileName(targetName);
		if (normalizedDir === null || normalizedName === null) {
			return jsonError(400, 'INVALID_TARGET', '目标路径/文件名无效：仅允许中文、字母、数字、下划线、短横线和点');
		}
		const finalTarget = normalizedDir ? `${normalizedDir}/${normalizedName}` : normalizedName;

		// 源必须存在，目标必须不存在（防覆盖）
		const sourceHead = await bucket.head(sourceKey);
		if (!sourceHead) {
			return jsonError(404, 'SOURCE_NOT_FOUND', '源文件不存在');
		}
		const targetHead = await bucket.head(finalTarget);
		if (targetHead) {
			return jsonError(409, 'TARGET_EXISTS', '目标位置已存在同名文件');
		}

		await bucket.copy(finalTarget, sourceKey);
		// 确认复制成功后再删源（避免丢文件）
		const verify = await bucket.head(finalTarget);
		if (!verify) {
			return jsonError(500, 'COPY_FAILED', '复制失败，源文件保留');
		}
		await bucket.delete(sourceKey);
		await invalidateStatsCache(env);

		return jsonOk({
			message: '重命名成功',
			key: finalTarget
		});
	} catch (error) {
		console.error('Rename error:', error);
		return jsonError(500, 'RENAME_FAILED', '重命名失败');
	}
}

// 用量统计：总文件数/总体积/各文件夹占用/近 7 日上传（KV 缓存 1 小时，写操作主动失效）
async function handleStats(request, env, bucket) {
	try {
		const cacheKey = 'stats:root:v1';
		const cached = await env.INDEXES_KV.get(cacheKey);
		if (cached) {
			return new Response(cached, {headers: {'Content-Type': 'application/json'}});
		}

		const MAX_SCAN = 5000; // 统计扫描上限，超出按"至少"计
		let scanned = 0;
		let truncated = false;
		let r2Cursor;
		const total = {files: 0, bytes: 0};
		const folders = new Map(); // 顶层文件夹 → {files, bytes}
		const sevenDaysAgo = Date.now() - 7 * 86400000;
		let recentCount = 0;

		do {
			const page = await bucket.list({prefix: '', limit: 1000, cursor: r2Cursor});
			for (const object of page.objects) {
				if (object.key.endsWith('/.null')) continue;
				if (isTrashKey(object.key)) continue; // 回收站不计入统计
				scanned++;
				total.files++;
				total.bytes += object.size || 0;
				const slash = object.key.indexOf('/');
				if (slash !== -1) {
					const folder = object.key.slice(0, slash);
					const stat = folders.get(folder) || {files: 0, bytes: 0};
					stat.files++;
					stat.bytes += object.size || 0;
					folders.set(folder, stat);
				}
				if (object.uploaded && new Date(object.uploaded).getTime() >= sevenDaysAgo) {
					recentCount++;
				}
			}
			r2Cursor = page.truncated ? page.cursor : undefined;
			if (scanned >= MAX_SCAN) truncated = true;
		} while (r2Cursor && !truncated);

		const payload = JSON.stringify({
			success: true,
			totalFiles: total.files,
			totalBytes: total.bytes,
			scannedTruncated: truncated,
			folders: [...folders.entries()]
				.map(([name, s]) => ({name, files: s.files, bytes: s.bytes}))
				.sort((a, b) => b.bytes - a.bytes)
				.slice(0, 50),
			last7Days: recentCount,
			cachedAt: new Date().toISOString()
		});

		await env.INDEXES_KV.put(cacheKey, payload, {expirationTtl: 3600});

		return new Response(payload, {headers: {'Content-Type': 'application/json'}});
	} catch (error) {
		console.error('Stats error:', error);
		return jsonError(500, 'STATS_FAILED', '统计失败');
	}
}

async function uploadImageToR2(imageUrl, bucket, isDocument = false, userPath = '') {
	try {
		const response = await fetch(imageUrl);
		if (!response.ok) throw new Error('下载文件失败');

		const buffer = await response.arrayBuffer();

		// Telegram Bot API 限制机器人可下载文件最大 20MB，超限给出明确提示
		if (buffer.byteLength > TG_MAX_BYTES) {
			return {
				ok: false,
				error: 'FILE_TOO_LARGE',
				message: '文件超过 20MB（Telegram Bot API 下载上限），请改用网页端上传。'
			};
		}

		const uint8Array = new Uint8Array(buffer);

		const detectedType = detectImageType(uint8Array);
		if (!detectedType) {
			return {
				ok: false,
				error: 'UNSUPPORTED_TYPE',
				message: '只支持 JPG/PNG/GIF/WebP/BMP 格式文件'
			};
		}
		const date = new Date();
		const formattedDate = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, '0')}${String(date.getDate()).padStart(2, '0')}`;
		const shortUUID = crypto.randomUUID().split('-')[0];

		// Build file path with user prefix if provided
		let key = `${formattedDate}_${shortUUID}.${detectedType.ext}`;

		if (userPath) {
			const normalizedPath = sanitizeFolderPath(userPath);
			if (normalizedPath) {
				key = `${normalizedPath}/${key}`;
			}
		}

		// 不做服务端格式转换（旧实现的 arrayBufferToBase64 未定义且方案不成立，
		// 是 >500KB 上传必崩的根因；TG 发送的 photo 本身已经过 Telegram 压缩）
		await bucket.put(key, buffer, {
			httpMetadata: {
				contentType: detectedType.mime
			},
		});
		await invalidateStatsCache(env).catch(() => {});

		return {ok: true, key};
	} catch (error) {
		console.error('上传失败:', error);
		return {
			ok: false,
			error: 'SERVER_ERROR',
			message: '文件上传失败，请稍后再试。'
		};
	}
}

async function getFileUrl(fileId, botToken) {
	const response = await fetch(
		`https://api.telegram.org/bot${botToken}/getFile?file_id=${fileId}`
	);
	const data = await response.json();
	if (!data.ok || !data.result || !data.result.file_path) {
		throw new Error((data && data.description) || '获取文件下载地址失败');
	}
	return `https://api.telegram.org/file/bot${botToken}/${data.result.file_path}`;
}

async function sendMessage(chatId, text, apiUrl, options = {}) {
	await fetch(`${apiUrl}/sendMessage`, {
		method: 'POST',
		headers: {'Content-Type': 'application/json'},
		body: JSON.stringify({
			chat_id: chatId,
			text: text,
			...options
		}),
	});
}

// 带重试的 sendMessage：返回是否确认送达（TG API ok:true）
async function sendMessageReliable(chatId, text, apiUrl, options = {}) {
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			const response = await fetch(`${apiUrl}/sendMessage`, {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({
					chat_id: chatId,
					text: text,
					...options
				}),
			});
			const data = await response.json().catch(() => null);
			if (data && data.ok) return true;
			// 429 限流：等 retry_after 再试
			const retryAfter = data && data.parameters && data.parameters.retry_after;
			if (retryAfter) await new Promise(r => setTimeout(r, Math.min(retryAfter, 5) * 1000));
		} catch (e) { /* 网络异常，稍后重试 */ }
		await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
	}
	return false;
}

async function sendPhoto(chatId, photoUrl, apiUrl, caption = "", options = {}) {
	const response = await fetch(`${apiUrl}/sendPhoto`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			chat_id: chatId,
			photo: photoUrl,
			caption: caption,
			...options
		}),
	});
	return await response.json();
}
