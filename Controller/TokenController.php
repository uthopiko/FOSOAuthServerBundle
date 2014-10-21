<?php

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;

class TokenController
{
    /**
     * @var OAuth2
     */
    protected $server;
    
    protected $storage;

    /**
     * @param OAuth2 $server
     */
    public function __construct(OAuth2 $server, $storage)    
    {
        $this->server = $server;
        $this->storage = $storage;
    }

    /**
     * @param Request $request
     * @return type
     */
    public function tokenAction(Request $request)
    {
        try {
            if ($request->query->get('grant_type') == OAuth2::GRANT_TYPE_AUTH_CODE || $request->query->get('grant_type') == OAuth2::GRANT_TYPE_REFRESH_TOKEN) {
                $user = $this->storage->getUserFromAuthCode($request->query->get('code'));
                $token = $this->server->grantAccessToken($request);
                $data = json_decode($token->getContent());
                $this->storage->updateAccessToken($data, $user);
                return $token;
            }
            return $this->server->grantAccessToken($request);
        } catch (OAuth2ServerException $e) {
            return $e->getHttpResponse();
        }
    }
}
