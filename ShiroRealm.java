package com.jianpiao.shiro;

import com.alibaba.dubbo.config.annotation.Reference;
import com.jianpiao.api.IAccountService;
import com.jianpiao.api.IRoleMenuService;
import com.jianpiao.core.commons.dto.DataMessage;
import com.jianpiao.core.commons.utils.DictEnum;
import com.jianpiao.domain.Account;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * @author: masterYI
 * @date: 2017/11/30
 * @time: 10:43
 * Description:用户认证授权
 */
@Component
public class ShiroRealm extends AuthorizingRealm {

    @Reference
    private IRoleMenuService roleMenuService;

    @Reference
    private IAccountService accountService;


    /**
     * 用户授权
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        String account = (String) principalCollection.getPrimaryPrincipal();
        List<String> permsList = new ArrayList<>();
        DataMessage dataMessage = roleMenuService.userMenu(account);
        if (dataMessage.isSuccess()) {
            permsList = (List<String>) dataMessage;
        }
        if (CollectionUtils.isNotEmpty(permsList)) {
            List<String> collect = permsList.stream().filter(url -> StringUtils.isNotBlank(url)).collect(Collectors.toList());
            Set<String> permissions = new HashSet<>(collect);
            authorizationInfo.setStringPermissions(permissions);
        }
        return authorizationInfo;
    }

    /**
     * 用户认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) authenticationToken;
        String account = upToken.getUsername();
        if (StringUtils.isBlank(account)) {
            throw new UnknownAccountException();
        }
        Account user = new Account();
        DataMessage dataMessage = accountService.getAccountPass(account);
        if (dataMessage.isSuccess()) {
            user = (Account) dataMessage.getData();
        }
        //判断用户是否存在
        if (user == null) {
            throw new UnknownAccountException();
        }
        //判断用户状态
        if (user.getState() == null || DictEnum.ENABLE.state != user.getState()) {
            throw new LockedAccountException();
        }
        String password = user.getPassword();
        String salt = user.getSalt();
        return new SimpleAuthenticationInfo(account, password, ByteSource.Util.bytes(salt), this.getName());
    }

    @PostConstruct
    private void initShiroRealm() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");
        hashedCredentialsMatcher.setHashIterations(1024);
        this.setCredentialsMatcher(hashedCredentialsMatcher);
    }


}
