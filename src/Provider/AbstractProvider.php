<?php
declare(strict_types=1);

/**
 * User: qingpizi
 * Date: 2020/11/15
 * Time: 下午2:46
 */
namespace Qingpizi\OauthLogin\Provider;

use http\Client;

abstract class AbstractProvider
{
    /**
     * 应用的唯一标识。
     * @var string
     */
    protected $appId;

    /**
     * appId对应的密钥
     * @var string
     */
    protected $appSecret;

    /**
     * 登录回调地址
     * @var string
     */
    protected $callbackUrl;


    protected $extend;

    /**
     * 范围
     * @var void
     */
    protected $scope;

    public $openId;

    protected $unionId;

    public $isUseUnionId = false;

    public function __construct(string $appId, string $appSecret, $callbackUrl = null, $extend = [])
    {
        $this->appId = $appId;
        $this->appSecret = $appSecret;
        $this->callbackUrl = $callbackUrl;
    }

    /**
     * 把jsonp转为php数组
     * @param string $jsonp jsonp字符串
     * @param boolean $assoc 当该参数为true时，将返回array而非object
     * @return array
     */
    public function jsonp_decode($jsonp, $assoc = false)
    {
        $jsonp = trim($jsonp);
        if(isset($jsonp[0]) && $jsonp[0] !== '[' && $jsonp[0] !== '{') {
            $begin = strpos($jsonp, '(');
            if(false !== $begin)
            {
                $end = strrpos($jsonp, ')');
                if(false !== $end)
                {
                    $jsonp = substr($jsonp, $begin + 1, $end - $begin - 1);
                }
            }
        }
        return \json_decode($jsonp, $assoc);
    }

    /**
     * http_build_query — 生成 URL-encode 之后的请求字符串
     * @param $queryData
     * @param string $numericPrefix
     * @param string $argSeparator
     * @param int $encType
     * @return string
     */
    public function http_build_query($queryData, $numericPrefix = '', $argSeparator = '&', $encType = PHP_QUERY_RFC1738)
    {
        return \http_build_query($queryData, $numericPrefix, $argSeparator, $encType);
    }

}