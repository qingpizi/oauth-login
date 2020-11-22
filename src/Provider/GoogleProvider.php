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
use Qingpizi\OauthLogin\Exception\ApiException;

class GoogleProvider extends AbstractProvider implements ProviderInterface
{
    use HasHttpRequest;

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
        return 'https://accounts.google.com/o/oauth2/v2/auth?' . $this->http_build_query($queryData);
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
        $url = 'https://www.googleapis.com/oauth2/v4/token';
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
            'prettyPrint' => 'false',
        ];

        $url = 'https://www.googleapis.com/userinfo/v2/me';
        $content = $this->get($url, $queryData, [
            'Authorization' => 'Bearer ' . $accessToken,
        ]);
        $result = json_decode($content, true);

        if(isset($result['error'])) {
            throw new ApiException($result['error_description']);
        } else {
            $this->unionId = $result['id'];
            $this->openId = $result['open_id'] ?? '';
            return $result;
        }
    }
}