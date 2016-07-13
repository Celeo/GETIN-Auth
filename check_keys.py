from hr.app import *


with open('results.txt', 'w') as f:
    for key in APIKey.query.all():
        try:
            auth = xmlapi.auth(keyID=key.key, vCode=key.code)
            result = auth.account.APIKeyInfo()
            if not result.key.accessMask == app.config['API_KEY_MASK']:
                f.write('Invalid key #{}, mask is {} but needs {}\n'.format(
                    key.id,
                    result.key.accessMask,
                    app.config['API_KEY_MASK']
                ))
        except Exception as e:
            f.write('Invalid key #{}, exception: {}'.format(
                key.id,
                str(e)
            ))
