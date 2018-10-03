<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\UserCredentialsInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class UserCredentials implements GrantTypeInterface
{
    private $userInfo;

    protected $storage;

    /**
     * @param OAuth2\Storage\UserCredentialsInterface $storage REQUIRED Storage class for retrieving user credentials information
     */
    public function __construct(UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'password';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (is_null($request->request("password")) || !$request->request("username")) {
            $response->setError(400, 'invalid_request', 'Kehilangan parameter: "username" dan "password" diwajibkan ada');

            return null;
        }

        if (!$this->storage->checkUser($request->request("username"))) {
            // $response->setError(401, 'invalid_grant', 'Invalid username and password combination or user is not active');
            $response->setError(401, 'invalid_grant', 'Maaf, email Anda belum terdaftar. <a href="'.linkservice('FRONTEND').'register" style="display:inline-block">Daftarkan sekarang.</a>');

            return null;
        }

        if (!$this->storage->checkUserCredentials($request->request("username"), $request->request("password"))) {
            // $response->setError(401, 'invalid_grant', 'Invalid username and password combination or user is not active');
            $response->setError(401, 'invalid_grant', 'Kata sandi yang anda masukkan salah');

            return null;
        }

        if (!$this->storage->checkUserActivation($request->request("username"))) {
            // $response->setError(401, 'invalid_grant', 'Invalid username and password combination or user is not active');
            $response->setError(401, 'invalid_grant', 'Akun belum aktif. Silahkan lakukan verifikasi email');

            return null;
        }

        $userInfo = $this->storage->getUserDetails($request->request("username"));

        if (empty($userInfo)) {
            $response->setError(400, 'invalid_grant', 'Tidak dapat menemukan informasi pengguna');

            return null;
        }

        if (!isset($userInfo['user_id'])) {
            throw new \LogicException("Anda harus menyisipkan user_id pada respon array dari getUserDetails");
        }

        $this->userInfo = $userInfo;

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->userInfo['user_id'];
    }

    public function getScope()
    {
        return isset($this->userInfo['scope']) ? $this->userInfo['scope'] : null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        return $accessToken->createAccessToken($client_id, $user_id, $scope);
    }
}
