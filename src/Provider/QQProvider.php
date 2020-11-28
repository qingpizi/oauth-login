<?php
declare(strict_types=1);

use Qingpizi\OauthLogin\Contract\ProviderInterface;

/**
 * User: qingpizi
 * Date: 2020/11/15
 * Time: 上午10:25
 */
namespace Qingpizi\OauthLogin\Provider;

use Qingpizi\OauthLogin\Contract\AccessTokenInterface;
use Qingpizi\OauthLogin\Contract\AuthUriInterface;
use Qingpizi\OauthLogin\Contract\IdentifierInterface;
use Qingpizi\OauthLogin\Contract\UserInfoInterface;
use Qingpizi\OauthLogin\Traits\HasHttpRequest;
use Qingpizi\OauthLogin\Exception\ApiException;

class QQProvider extends AbstractProvider implements  AuthUriInterface, AccessTokenInterface, IdentifierInterface, UserInfoInterface
{

    use HasHttpRequest;

    protected $scope = ['get_user_info'];

    public function getAuthUri(string $state = ''): string
    {
        $queryData = [
            'client_id' => $this->appId,
            'redirect_uri' => $this->callbackUrl,
            'scope' => $this->scope,
            'response_type' => 'code',
            'state' => $state,
        ];
        return 'https://graph.qq.com/oauth2.0/authorize?' . $this->http_build_query($queryData);
    }

    public function getAccessToken(string $code): string
    {
        $queryData = [
            'client_id' => $this->appId,
            'client_secret' => $this->appSecret,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];
        $url = 'https://graph.qq.com/oauth2.0/token';
        $content = $this->get($url, $queryData);
        $jsonData = json_decode($content, true);
        if($jsonData) {
            throw new ApiException($jsonData['error_description'], $jsonData['error']);
        }
        parse_str($content, $result);
        if(isset($result['code']) && $result['code'] != 0) {
            throw new ApiException($result['msg'], $result['code']);
        } else {
            return $result['access_token'];
        }

    }

    public function getIdentifier(string $accessToken): string
    {
        $queryData = [
            'unionid' => $this->isUseUnionId ? 1 : 0,  // 返回用户唯一标识
            'access_token' => $accessToken
        ];

        $url = 'https://graph.qq.com/oauth2.0/me';
        $content = $this->get($url, $queryData);
        $result = $this->jsonp_decode($content, true);
        if(isset($result['error'])) {
            throw new ApiException($result['error_description'], $result['error']);
        } else {
            $this->openId = $result['openid'];
            return $this->isUseUnionId ? $result['unionid'] : $result['openid'];
        }

    }

    public function getUserInfo(string $accessToken): array
    {
        $queryData = [
            'access_token' => $accessToken,
            'openid' => $this->open_id,
            'oauth_consumer_key' => $this->appId,
        ];
        $url = 'https://graph.qq.com/user/get_user_info';
        $content = $this->get($url, $queryData);
        $result = $this->jsonp_decode($content, true);
        if(isset($result['ret']) && $result['ret'] != 0) {
            throw new ApiException($result['msg'], $result['ret']);
        } else {
            return $result;
        }
    }

}