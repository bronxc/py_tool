coop_searcher.py 用于遍历所有函数并查找特征函数的工具，扩展性不强，已废弃

IDAResolve.py 一个用来解析所有函数的框架类，可获得函数的 CFG

IDASearcher.py 使用 IDAResolve.py 编写的一个用于查找特定特征函数的工具，目前已经集成 COOP 所有功能，以及查找函数指针功能

VTableToDefinnition.py 用于将选中区域的虚表转化为类定义
