<?php
declare(strict_types=1);
/**
 * User: qingpizi
 * Date: 2020/11/28
 * Time: 下午8:43
 */

namespace Qingpizi\OauthLogin\Contract;


interface AuthUriInterface
{
    public function getAuthUri(string $state = ''): string;
}