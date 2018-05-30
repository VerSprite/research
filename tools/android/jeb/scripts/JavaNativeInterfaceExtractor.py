from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code import ICodeItem
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit

class JavaNativeInterfaceExtractor(IScript):

    def __init__(self):
        self.context = None
        self.units = None

    def run(self, ctx):
        self.context = ctx.getEnginesContext()
        if not self.context:
            return
        # Assuming a single classes.dex
        unit = RuntimeProjectUtil.findUnitsByType(self.context.getProjects()[0], IDexUnit, False)[0]
        classez = unit.getClasses()
        for c in classez:
            if c:
                methods = c.getMethods()
                if methods:
                    for m in methods:
                        self.extractNativeMethods(m)
    
    def extractNativeMethods(self, method):
        """
        := Extract access flags for a given method  
        """
        if method.getGenericFlags() & ICodeItem.FLAG_NATIVE == ICodeItem.FLAG_NATIVE:
            print("jni -> {}".format(method.getSignature(True).replace('L', '').replace('/', '.').replace(';', '')))
        return
