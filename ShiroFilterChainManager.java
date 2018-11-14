package com.jianpiao.shiro;

import com.alibaba.dubbo.config.annotation.Reference;
import com.jianpiao.api.IMenuService;
import com.jianpiao.core.commons.dto.DataMessage;
import com.jianpiao.domain.Menu;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.NamedFilterList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author masterYI
 */
@Component
public class ShiroFilterChainManager {


    @Autowired
    private DefaultFilterChainManager defaultFilterChainManager;

    @Reference
    private IMenuService menuService;

    private Map<String, NamedFilterList> defaultFilterChains;


    @PostConstruct
    public void init() {

        defaultFilterChains = new HashMap<>(defaultFilterChainManager.getFilterChains());
    }

    public void initFilterChains(List<Menu> menuList) {
        //1、首先删除以前老的filter chain并注册默认的
        defaultFilterChainManager.getFilterChains().clear();
        if (defaultFilterChains != null) {
            defaultFilterChainManager.getFilterChains().putAll(defaultFilterChains);
        }

        //2、循环URL Filter 注册filter chain
        for (Menu menu : menuList) {
            if (menu == null) {
                continue;
            }
            String url = menu.getUrl();
            if (StringUtils.isBlank(url)) {
                continue;
            }
            defaultFilterChainManager.addToChain(url, "perms", url);

        }

    }

    /**
     * 注册拦截器到shiro，spring容器启动或对角色权限进行增删改时会生效
     */
    @PostConstruct
    public void initFilterChain() {
        List<Menu> menus = new ArrayList<>();
        DataMessage dataMessage = menuService.selectAllMenu();
        if (dataMessage.isSuccess()) {
            menus = (List<Menu>) dataMessage.getData();
        }
        initFilterChains(menus);
    }


}

