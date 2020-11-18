<?php
declare(strict_types=1);

/**
 * Created by PhpStorm
 * User: qingpizi
 * Date: 2020/11/15
 * Time: 上午10:05
 */
namespace Qingpizi\OauthLogin\Contract;

interface ProviderInterface
{

    public function getAuthUri(string $state = ''): string;

    public function getAccessToken(string $code): string;

    public function getIdentifier(string $accessToken): string;

    public function getUserInfo(string $accessToken): array;

}