import praw


reddit = praw.Reddit('GETIN EVE Alliance:v0.1 (by /u/Celeodor)')


class OAuth:

    def __init__(self, client_id, secret, authorize_url, callback_url, scope):
        self.client_id = client_id
        self.secret = secret
        self.authorize_url = authorize_url
        self.callback_url = callback_url
        self.scope = scope

    def get_authorize_url(self):
        return '{}?response_type=code&redirect_uri={}&client_id={}&scope={}'.format(self.authorize_url,
            self.callback_url, self.client_id, self.scope)

    def get_token(self, code):
        raise NotImplementedError


class RedditOAuth(OAuth):

    def __init__(self, client_id, secret, callback_url, scope=''):
        super().__init__(client_id, secret, '', callback_url, scope)
        reddit.set_oauth_app_info(client_id, secret, callback_url)

    def get_authorize_url(self):
        return reddit.get_authorize_url('getin-hr', 'identity', False)

    def get_token(self, code):
        reddit.get_access_information(code)
        return reddit.get_me().name
