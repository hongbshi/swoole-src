--TEST--
swoole_mysql_coro: mysql query timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function (){
    $mysql = new Swoole\Coroutine\MySQL();
    $res = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    if (!$res)
    {
        fail:
        echo "CONNECT ERROR\n";
        return;
    }
    $s = microtime(true);
    $timeout = mt_rand(100, 500) / 1000;
    $ret = $mysql->query('select sleep(1)', $timeout);
    time_approximate($timeout, microtime(true) - $s);
    if (!$ret)
    {
        assert($mysql->errno === SOCKET_ETIMEDOUT);
        echo $mysql->error."\n";
    }
    else
    {
        var_dump($ret);
    }
});
swoole_event::wait();
?>
--EXPECT--
query timeout
