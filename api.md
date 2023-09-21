接口文档 https://chromium.googlesource.com/infra/infra/+/HEAD/appengine/monorail/doc/api.md#monorail_issues_list

1. search 查询规则  https://bugs.chromium.org/p/chromium/issues/advsearch
2. query 用法 
    * 在with_strings="CVE cve"搜包含5317个结果, withstring是在issues的全部内容里面搜索，可能未分配cve只是在comment中提及
    * 在labels搜包含2855个结果  中肯的方法
