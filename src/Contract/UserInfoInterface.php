<?php
declare(strict_types=1);
/**
 * User: qingpizi
 * Date: 2020/11/28
 * Time: 下午8:44
 */

namespace Qingpizi\OauthLogin\Contract;


interface UserInfoInterface
{
    public function getUserInfo(string $accessToken): array;
}