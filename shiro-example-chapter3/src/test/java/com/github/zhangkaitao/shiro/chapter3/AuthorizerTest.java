package com.github.zhangkaitao.shiro.chapter3;

import junit.framework.Assert;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.junit.Test;

/**
 * 
 * <pre>
 * 字符串通配符权限
        规则："资源标识符:操作:对象实例ID" 即对哪个资源的哪个实例可以进行什么操作。
        其默认支持通配符权限字符串，":"表示资源/操作/实例的分割符；","表示操作的分割；
        "*"表示任意资源/操作/实例。
 * 
 * 
 * 权限：
 *     0 表示所有权限
 *     1 新增 0001
 *     2 修改 0010
 *     4 删除 0100
 *     8 查看 1000
 * 
 * </pre>
 * <p>
 * User: Zhang Kaitao
 * <p>
 * Date: 14-1-26
 * <p>
 * Version: 1.0
 */
public class AuthorizerTest extends BaseTest {

    @Test
    public void testIsPermitted() {
        login("classpath:shiro-authorizer.ini", "zhang", "123");
        // 判断拥有权限：user:create
        Assert.assertTrue(subject().isPermitted("user1:update"));
        Assert.assertTrue(subject().isPermitted("user2:update"));
        // 通过二进制位的方式表示权限
        Assert.assertTrue(subject().isPermitted("+user1+2"));// 修改权限
        Assert.assertTrue(subject().isPermitted("+user1+8"));// 查看权限
        Assert.assertTrue(subject().isPermitted("+user2+10"));// 修改及查看

        Assert.assertFalse(subject().isPermitted("+user1+4"));// 没有删除权限

        Assert.assertTrue(subject().isPermitted("menu:view"));// 通过MyRolePermissionResolver解析得到的权限
    }

    @Test
    public void testIsPermitted2() {
        login("classpath:shiro-jdbc-authorizer.ini", "zhang", "123");
        // 判断拥有权限：user:create
        Assert.assertTrue(subject().isPermitted("user1:update"));
        Assert.assertTrue(subject().isPermitted("user2:update"));
        // 通过二进制位的方式表示权限
        Assert.assertTrue(subject().isPermitted("+user1+2"));// 新增权限
        Assert.assertTrue(subject().isPermitted("+user1+8"));// 查看权限
        Assert.assertTrue(subject().isPermitted("+user2+10"));// 新增及查看

        Assert.assertFalse(subject().isPermitted("+user1+4"));// 没有删除权限

        Assert.assertTrue(subject().isPermitted("menu:view"));// 通过MyRolePermissionResolver解析得到的权限
    }

}
