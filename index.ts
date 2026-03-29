import {
    Context, ForbiddenError, Handler, Schema, Service, superagent, SystemModel,
    TokenModel, UserFacingError, ValidationError,
} from 'hydrooj';

const icon = '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect width="100" height="100" rx="20" fill="#E5E7EB"/><text x="50" y="68" font-family="Arial, Helvetica, sans-serif" font-size="48" font-weight="bold" fill="#4B5563" text-anchor="middle">CP</text></svg>';

export default class LoginWithCPOAuthService extends Service {
    static inject = ['oauth'];
    static Config = Schema.object({
        id: Schema.string().description('CP OAuth ID').required(),
        secret: Schema.string().description('CP OAuth Secret').role('secret').required(),
        endpoint: Schema.string().description('CP OAuth Endpoint').default('https://auth.luogu.me'),
        canRegister: Schema.boolean().default(true),
    });

    constructor(ctx: Context, config: ReturnType<typeof LoginWithCPOAuthService.Config>) {
        super(ctx, 'oauth.cpoauth');

        // 定义 get 函数：当用户点击登录按钮时执行
        const getHandler = async function(this: Handler) {
            const endpoint = config.endpoint || 'https://auth.luogu.me';
            const redirectUri = `${SystemModel.get('server.url')}oauth/cpoauth/callback`;

            const [state] = await TokenModel.add(TokenModel.TYPE_OAUTH, 600, { redirect: this.request.referer });

            this.response.redirect = `${endpoint}/oauth/authorize?` +
                `response_type=code` +
                `&client_id=${config.id}` +
                `&redirect_uri=${encodeURIComponent(redirectUri)}` +
                `&scope=openid profile email` +
                `&state=${state}`;
        };

        // 定义 callback 函数：用户授权后回调
        const callbackHandler = async function({ state, code }) {
            const s = await TokenModel.get(state, TokenModel.TYPE_OAUTH);
            if (!s) throw new ValidationError('token');

            const url = SystemModel.get('server.url');
            const endpoint = config.endpoint || 'https://auth.luogu.me';

            // 使用 code 换取 access_token
            const res = await superagent.post(`${endpoint}/api/oauth/token`)
                .send({
                    grant_type: 'authorization_code',
                    client_id: config.id,
                    client_secret: config.secret,
                    code,
                    redirect_uri: `${url}oauth/cpoauth/callback`,
                    state,
                })
                .set('accept', 'application/json');

            if (res.body.error) {
                throw new UserFacingError(
                    res.body.error, res.body.error_description, res.body.error_uri,
                );
            }

            const { access_token } = res.body;

            // 使用 access_token 获取用户信息
            const userInfo = await superagent.get(`${endpoint}/api/oauth/userinfo`)
                .set('Authorization', `Bearer ${access_token}`)
                .set('accept', 'application/json');

            const userData = userInfo.body;

            const ret = {
                _id: `${userData.sub || userData.id}@cpoauth.local`,
                email: userData.email,
                bio: userData.bio || '',
                uname: [userData.display_name, userData.username].filter((i) => i),
                avatar: userData.avatar_url || '',
            };

            await TokenModel.del(s._id, TokenModel.TYPE_OAUTH);
            if (!ret.email) throw new ForbiddenError("You don't have a verified email.");
            return ret;
        };

        // 注册 OAuth 模块
        ctx.oauth.provide('cpoauth', {
            text: 'Login with CP OAuth',
            name: 'CP OAuth',
            icon,
            canRegister: config.canRegister,
            callback: callbackHandler,
            get: getHandler,
        });

        ctx.i18n.load('zh', {
            'Login with CP OAuth': '使用 CP OAuth 登录',
        });
    }
}