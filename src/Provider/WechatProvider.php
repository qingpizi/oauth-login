<?php
declare(strict_types=1);

/**
 * Created by PhpStorm
 * User: qingpizi
 * Date: 2020/11/15
 * Time: 上午10:25
 */
namespace Qingpizi\OauthLogin\Provider;

use Qingpizi\OauthLogin\Contract\ProviderInterface;
use Qingpizi\OauthLogin\Traits\HasHttpRequest;
use Qingpizi\OauthLogin\Exception\ApiException;

class WechatProvider extends AbstractProvider implements ProviderInterface
{
    use HasHttpRequest;

    protected $scope = 'snsapi_login';

    public function getAuthUri(string $state = ''): string
    {
        $queryData = [
            'appid' => $this->appId,
            'redirect_uri' => $this->callbackUrl,
            'scope' => $this->scope,
            'response_type' => 'code',
            'state' => $state,
            'connect_redirect' => 1
        ];
        return 'https://open.weixin.qq.com/connect/qrconnect?' . $this->http_build_query($queryData);
    }

    public function getAccessToken(string $code): string
    {
        $queryData = [
            'appid' => $this->appId,
            'secret' => $this->appSecret,
            'code' => $code,
            'grant_type' => 'authorization_code',
        ];
        $url = 'https://api.weixin.qq.com/sns/oauth2/access_token';
        $content = $this->get($url, $queryData);
        $result = json_decode($content, true);

        if(isset($result['errcode']) && $result['errcode'] != 0) {
            throw new ApiException($result['errmsg'], $result['errcode']);
        } else {
            $this->openId = $result['openid'];
            $this->unionId = $result['unionid'];
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
            'openid' => $this->open_id,
            'oauth_consumer_key' => $this->appId,
        ];
        $url = 'https://api.weixin.qq.com/sns/userinfo';
        $content = $this->get($url, $queryData);
        $result = json_decode($content, true);
        if(isset($result['errcode']) && $result['errcode'] != 0) {
            throw new ApiException($result['errmsg'], $result['errcode']);
        } else {
            return $result;
        }
    }
}