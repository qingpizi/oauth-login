<?php
declare(strict_types=1);
/**
 * User: qingpizi
 * Date: 2020/11/22
 * Time: 下午8:56
 */

namespace Qingpizi\OauthLogin\Provider;

use Qingpizi\OauthLogin\Contract\AccessTokenInterface;
use Qingpizi\OauthLogin\Contract\IdentifierInterface;
use Qingpizi\OauthLogin\Exception\ApiException;
use Qingpizi\OauthLogin\Exception\LogicException;
use Qingpizi\OauthLogin\Traits\HasHttpRequest;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JwtAuth\Jwt;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use CoderCat\JWKToPEM\JWKConverter;

class AppleProvider extends AbstractProvider implements AccessTokenInterface, IdentifierInterface
{
    use HasHttpRequest;

    public function getAccessToken(string $code): string
    {
        $bodyData = [
            'client_id' => $this->appId,
            'client_secret' => $this->getClientSecret(),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];
        $url = 'https://appleid.apple.com/auth/token';
        $content = $this->post($url, $bodyData);
        $result = \json_decode($content, true);

        if(isset($result['error'])) {
            throw new ApiException($result['error_description']);
        } else {
            return $result['access_token'];
        }
    }

    public function getIdentifier(string $accessToken): string
    {
        $tokenObject = (new Parser())->parse($accessToken);
        if (! $tokenObject->hasHeader('kid')) {
            throw new LogicException("The kid doesn't exist in token.");
        }
        $kid = $tokenObject->getHeader('kid');
        $authKey = $this->getAuthKeys($kid);
        $jwkConverter = new JWKConverter();
        $publicKey = $jwkConverter->toPEM($authKey);
        $rsaSha256 = new RsaSha256();
        $result = $tokenObject->verify($rsaSha256, $publicKey);
        if (! $result) {
            throw new LogicException("The token verify failed.");
        }
        return $this->unionId = $tokenObject->getClaim("sub");
    }

    private function getClientSecret(): string
    {
        if (empty($this->extend['private_key'])) {
            throw new LogicException("The private_key illegal.");
        }

        if (empty($this->extend['team_id'])) {
            throw new LogicException("The team_id illegal.");
        }

        if (empty($this->extend['key_id'])) {
            throw new LogicException("The key_id illegal.");
        }

        $time = time();
        $sub = $this->appId;
        $private = $this->extend['private_key'];
        $teamId = $this->extend['team_id'];
        $kid = $this->extend['key_id'];
        $aud = 'https://appleid.apple.com';

        $builder = (new Builder())
            ->issuedBy($teamId) // 设置jwt的jti
            ->issuedAt($time)// (iat claim) 发布时间
            ->permittedFor($aud)
            ->relatedTo($sub)
            ->expiresAt($time + 86400)// 到期时间
            ->withHeader('alg', 'ES256')
            ->withHeader('kid', $kid);
        $sha256 = new EcdsaSha256();
        return (string) $builder->getToken($sha256, new Key($private));
    }

    /**
     * 获取apple认证key
     * @param string $kid
     * @return array
     * @throws \Exception
     */
    private function getAuthKeys(string $kid): array
    {
        $url = 'https://appleid.apple.com/auth/keys';
        $content = $this->get($url);
        $result = \json_decode($content, true);
        $authKey = '';
        foreach ($result['keys'] as $key) {
            if ($key['kid'] === $kid) {
                $authKey = $key;
                break;
            }
        }
        if (! $authKey) {
            throw new LogicException("The auth key failed to get.");
        }
        return $authKey;
    }
}