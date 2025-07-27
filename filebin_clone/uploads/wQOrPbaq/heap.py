def longestCommonPrefix( nums):
        suffix = 1
        prefix = 1
        ans = -999999   
        n = len(nums)
        for i in range(len(nums)):
           suffix = suffix*nums[n-i-1]
           prefix = prefix*nums[i]
           ans = max(suffix,prefix,ans)
           if suffix == 0:
            suffix = 1
           if prefix == 0:
            prefix = 1
        return ans

longestCommonPrefix([2,-5,2,-4,3,-1])