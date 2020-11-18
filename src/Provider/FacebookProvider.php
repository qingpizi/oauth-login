<?php
declare(strict_types=1);

/**
 * Created by PhpStorm
 * User: qingpizi
 * Date: 2020/11/15
 * Time: 上午10:26
 */
namespace Qingpizi\OauthLogin\Provider;

use Qingpizi\OauthLogin\Contract\ProviderInterface;
use Qingpizi\OauthLogin\Traits\HasHttpRequest;

class FacebookProvider extends AbstractProvider implements ProviderInterface
{
    use HasHttpRequest;

    public $openId;

    public $isUseUnionId = false;

    protected $unionId;

    protected $scope = 'snsapi_login';

    public function getAuthUri(string $state = ''): string
    {
        $queryData = [
            'client_id' => $this->appId,
            'redirect_uri' => $this->callbackUrl,
            'scope' => $this->scope,
            'response_type' => 'code',
            'state' => $state,
        ];
        return 'https://www.facebook.com/v3.2/dialog/oauth?' . $this->http_build_query($queryData);
    }

    public function getAccessToken(string $code): string
    {
        $queryData = [
            'client_id' => $this->appId,
            'client_secret' => $this->appSecret,
            'code' => $code,
            'redirect_uri' => $this->callbackUrl,
        ];
        $url = 'https://www.facebook.com/v3.2/oauth/access_token';
        $content = $this->get($url, $queryData);
        $result = json_decode($content, true);

        if(isset($result['error'])) {
            throw new ApiException($result['error_description']);
        } else {
            return $result['access_token'];
        }
    }

    public function getIdentifier(string $accessToken): string
    {
        return $this->isUseUnionId ? $this->unionId : $this->openId;
    }

    public function getUserInfo(string $accessToken): array
    {
        $queryData = [
            'access_token' => $accessToken,
            'appsecret_proof' => hash_hmac('sha256', $accessToken, $this->appSecret),
            'fields' => implode(',', ['first_name', 'last_name', 'email', 'gender', 'verified', 'birthday', 'picture', 'token_for_business'])
        ];

        if ($this->isUseUnionId) {
            array_push($queryData['fields'], 'token_for_business');
        }

        $url = 'https://www.facebook.com/v3.2/me';
        $content = $this->get($url, $queryData);
        $result = json_decode($content, true);

        if(isset($result['error'])) {
            throw new ApiException($result['error_description']);
        } else {
            if ($this->isUseUnionId) {
                $this->unionId = $result['token_for_business'];
            }
            $this->openId = $result['user_id'];
            return $result;
        }
    }
}