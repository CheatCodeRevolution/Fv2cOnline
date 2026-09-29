local gg = gg
local info = gg.getTargetInfo()
local orig = {}
local xg = {}
local versionName = info.versionName
local versionCode = info.versionCode
local gameName = info.label
local package = info.packageName
local version = info.versionName

local GoC_PinList = { "PowerPin_ExtraPeachy_14d", "PowerPin_ReadyEddie_3d", "PowerPin_CashBunny_30d", "PowerPin_SoupStirrir_7d", "PowerPin_DogDrop_14d", "PowerPin_SpecialSeedDelivery_7d", "PowerPin_BoatRacePoints_01", "PowerPin_Rainbow_01", "PowerPin_ButterChurner_5d", "PowerPin_ExtremeExpansion_01", "PowerPin_ExtraStamps_01", "PowerPin_MineralUpgrade_01", "PowerPin_SpeedUpPrizedAnimal_01", "PowerPin_BarnUpgrade_01", "MakeItRainPin_01", "GoneFishingPin_01", "AncientMarinerPin_01", "ReadyEddiePin_01", "SpringSheepPin_01", "SweetToothPin_01", "EggtasticPin_01", "HolyCowPin_01", "PondWaitTime_Level3", "OldMillWaitTime_Level3", "PierWaitTime_Level3", "GladeWaitTime_Level3", "WaterTiles_Pin2", "WaterTiles_Pin1", "FestiveFinderPin_01", "MaxRefreshPin_01", "PeppyProduction_boost_consumable" };
local GoC_ItemList = { "animalCount", "Blue_Ribbon_01", "Boost_Bell_01","BattlePass_Token", "coin", "CountyFair_Points", "Dinner_Bell_01", "FarmCup_Points", "Lighthouse_01_certificate", "MissionPursuit_Token", "Mineral_01", "MysteryCollection_Social_Token", "Net_Common_01", "Net_Uncommon_01", "Net_Rare_01", "OrderBoard_02_certificate", "Red_Ribbon_01", "Seashell_01", "Stamp_Rare_01", "Stamp_Common_01", "Stamp_Uncommon_01", "VipClub_Token", "WholeSaler_01_certificate", "Yellow_Ribbon_01", "ZooTokenAnimal", "ZooTokenAxe", "ZooTokenRubber", "ZooTokenShear", "ZooTokenStamp", "diamondglove", "elbowgrease", "key", "speedseed", "timber" };
local GoC_SeaItemList = { "Ale_Mug_01", "Antique_Diving_Helmet_01", "Apple_01", "Apple_01_Bonus", "Apple_01_UpgradeMill", "Apple_Cider_01", "Apple_Pie_01", "Baked_Herring_01", "Baked_Potato_01", "Barn_Nail_01", "Barn_Padlock_01", "Bass_01", "Beeswax_Candle_01", "Birdhouse_Item_01", "Black_Rice_01", "Black_Rice_Pudding_01", "Black_Rice_Risotto_01", "Black_Rice_Sushi_01", "Black_Rice_and_Salmon_01", "Black_Veggie_Risotto_01", "Blackberries_01", "Blackberry_Custard_01", "Blackberry_Jelly_01", "Blackberry_Pie_01", "Blackberry_Tart_01", "Blanket_01", "Blueberries_01", "Blueberry_Granola_Muffin_01", "Blueberry_Jam_01", "Blueberry_Pancakes_01", "Bottle_01", "Brass_01", "Brie_Cheese_01", "Butter_01", "Buttermilk_Biscuit_01", "Cajun_Crab_01", "Candied_Cranberries_01", "Canvas_01", "Canvas_Tote_01", "Carrot_01", "Carrot_01_UpgradeMill", "Carrot_Cake_01", "Cat_Stuffed_Animal_01", "Cedar_Plank_Trout_01", "Cedar_Wood_01", "Champagne_01", "Chardonnay_01", "Cheesy_Urchin_Risotto_01", "Chives_01", "Clam_01", "Clam_Chowder_01", "Clam_Urchin_Paella_01", "Clay_01", "Clay_01_UpgradeMill", "Compass_01", "Copper_01", "Copper_Button_01", "Corn_01", "Corn_01_UpgradeMill", "Corn_Husk_Doll_01", "Cove_Punch_01", "Cow_Milk_01", "Cow_Milk_01_UpgradeMill", "Crab_01", "Crab_Cakes_01", "Crab_Souffle_01", "Cranberries_01", "Cranberry_Apple_Puff_Bono_01", "Cranberry_Jam_01", "Cranberry_Muffins_01", "Cranberry_Sauce_Bono_01", "Cranberry_Scones_01", "Deviled_Eggs_01", "Dog_Stuffed_Animal_01", "Dried_Fruit_01", "Duck_Feathers_01", "Duck_Stuffed_Animal_01", "Egg_01", "Egg_01_UpgradeMill", "Egg_Whites_01", "Farmers_Soup_01", "Fish_And_Chips_01", "Fish_Bowl_01", "Fish_Sauce_01", "Fishermans_Hat_01", "Flour_01", "Gelato_01", "Glass_Float_01", "Glass_Horse_01", "Goat_Cheese_01", "Goat_Milk_01", "Goat_Milk_01_UpgradeMill", "Granola_01", "Grape_Juice_01", "Herb_Butter_01", "Herring_01", "Herring_Potato_Salad_01", "Honey_Butter_01", "Honeycomb_01", "Honeycomb_01_UpgradeMill", "Jacket_01", "Jar_01", "Knit_Cap_01", "Krill_01", "Krill_Cakes_01", "Krill_Fries_01", "Krill_Potato_01", "Krill_Salad_01", "Krill_Tortilla_01", "Lemon_01", "Lemon_01_UpgradeMill", "Lemon_Gelato", "Lemon_Scented_Candle_01", "Lemon_Tart_01", "Lemon_Yogurt_01", "Lemon_Zest_01", "Lemonade_01", "Light_Bulb_01", "Loaded_Baked_Potato_01", "Lobster_01", "Lobster_Mac_And_Cheese_01", "Mac_And_Cheese_01", "Mermaid_Figurine_01", "Mineral_01", "Mint_01", "Mint_Chip_Cookies_01", "Mixed_Peppers_01", "Mixed_Peppers_01_UpgradeMill", "Oars_01", "Oatmeal_Cookies_01", "Oil_Lantern_01", "Ornate_Stein_01", "Overalls_01", "Pan_Fries_01", "Pan_Seared_Trout_01", "Peach_01", "Peach_01_UpgradeMill", "Peach_Yogurt_01", "Pear_01", "Pear_01_UpgradeMill", "Pear_Juice_01", "Pear_Preserves_01", "Pearl_01", "Pen_Shell_01", "Pen_Shell_Box_01", "Pen_Shell_Candle_01", "Pen_Shell_Jar_01", "Pen_Shell_Mermaid_01", "Pen_Shell_Mirror_01", "Pepper_Poppers_01", "Pillow_01", "Pinot_Noir_01", "Porcelain_Doll_01", "Pot_Pie_01", "Potato_01", "Potato_01_UpgradeMill", "Prized_Chicken_Feed_01", "Prized_Cow_Feed_01", "Prized_Goat_Feed_01", "Prized_Horse_Feed_01", "Prized_Pig_Feed_01", "Prized_Sheep_Feed_01", "Quartz_01", "Quilt_01", "Raggety_Doll_01", "Rain_Slicker_01", "Red_Grapes_01", "Red_Grapes_01_UpgradeMill", "Rocking_Chair_01", "Rose_Wine_01", "Royal_Sextant_01", "Salmon_01", "Salmon_Bisque_01", "Sandwich_and_Fries_01", "Scone_01", "Sea_Biscuits_01", "Sea_Salt_01", "Sea_Urchin_01", "Sea_Urchin_Gratin_01", "Sea_Urchin_Ice_Cream_01", "Seafood_Bruschetta_01", "Seafood_Chowder_01", "Seafood_Creole_01", "Seasoned_Clams_01", "Ship_In_A_Bottle_01", "Shovel_01", "Shrimp_01", "Shrimp_Gumbo_01", "Shrimp_Pasta_01", "Shrimp_Skewers_01", "Shrimp_and_Spinach_01", "Silver_Anchor_01", "Smoked_Salmon_01", "Smoked_Trout_01", "Socks_01", "Spinach_Bread_01", "Spinach_Caesar_01", "Spinach_Casserole_01", "Spinach_Salad_01", "Spyglass_01", "Strawberry_01", "Strawberry_01_UpgradeMill", "Strawberry_Gelato_Bono_01", "Strawberry_Jam_01", "Strawberry_Milk_01", "Strawberry_Shortcake_01", "Strawberry_Sundae_01", "Stuffed_Bass_01", "Sugar_01", "Sushi_and_Wasabi_01", "Sweet_Potato_Bites_01", "Swiss_Cheese_01", "Tangy_Ceviche_01", "Teddy_Bear_01", "Tin_01", "Tin_Button_01", "Tomato_01", "Tomato_01_UpgradeMill", "Tomato_Juice_01", "Trout_01", "Trout_Souflee_01", "Trout_and_Wilted_Spinach_01", "Trousers_01", "Wasabi_01", "Wasabi_Bread_01", "Water_Spinach_01", "Wheat_01", "Wheat_01_UpgradeMill", "Whistle_01", "White_Grapes_01", "White_Grapes_01_UpgradeMill", "Wind_Chime_01", "Wool_01", "Wool_01_UpgradeMill", "Woolen_Scarf_01", "Yarn_Doll_01" };
local itemStringnt = { "Newshop_A_Line_Dress_01", "Newshop_Apricots_01", "Newshop_Artisan_Brooch_01", "Newshop_Baby_Wool_Set_01", "Newshop_Barley_01", "Newshop_Barley_Bagel_01", "Newshop_Barley_Bonbon_01", "Newshop_Barley_Cream_Bonbon_01", "Newshop_Black_Rice_Bagel_01", "Newshop_Blackberry_Cream_Torte_01", "Newshop_Boho_Dress_01", "Newshop_Boho_Fringe_Wrap_01", "Newshop_Boho_Market_Tote_01", "Newshop_Boho_Shawl_01", "Newshop_Brass_Perfume_Charm_01", "Newshop_Carolina_Reaper_01", "Newshop_Cedar_Aroma_Blend_01", "Newshop_Cedar_Farm_Piece_01", "Newshop_Cedar_Fragrance_Sticks_01", "Newshop_Cedar_Hanger_01", "Newshop_Cherries_01", "Newshop_Cherry_Bloom_01", "Newshop_Chive_Cream_Ganache_01", "Newshop_Chive_Egg_Taco_01", "Newshop_Classic_Trout_Pie_01", "Newshop_Clay_Barn_Tile_01", "Newshop_Clay_Farm_Brick_01", "Newshop_Coastal_Heat_Rub_01", "Newshop_Coffee_Beans_01", "Newshop_Color_Dye_01", "Newshop_Copper_Farm_Charm_01", "Newshop_Copper_Perfume_Holder_01", "Newshop_Cranberry_Butter_Pancake_01", "Newshop_Cranberry_Mango_Tart_01", "Newshop_Creamy_Milk_Bagel_01", "Newshop_Creamy_Salmon_Pie_01", "Newshop_Creamy_Trout_Quesadilla_01", "Newshop_Egg_Ganache_01", "Newshop_Everyday_Wool_Scarf_01", "Newshop_Farm_Craft_Dye_01", "Newshop_Farmhouse_Clay_Mug_01", "Newshop_Floral_Berry_Rub_01", "Newshop_Garden_Berry_Rub_01", "Newshop_Goat_Milk_Bonbon_01", "Newshop_Herb_Onion_Crepe_01", "Newshop_Herring_Barley_Pancake_01", "Newshop_Herring_Pot_Pie_01", "Newshop_Homemakers_Wool_Dress_01", "Newshop_Kitchen_Patch_Apron_01", "Newshop_Kiwi_01", "Newshop_Kiwi_Custard_Bagel_01", "Newshop_Kiwi_Empanadas_01", "Newshop_Kiwi_Soy_Bagel_01", "Newshop_Krill_Spinach_Taco_01", "Newshop_Lavender_01", "Newshop_Lavender_Berry_Scoop_01", "Newshop_Lavender_Cherry_Scoop_01", "Newshop_Lavender_Cooler_01", "Newshop_Lavender_Cranberry_Scoop_01", "Newshop_Lavender_Cream_Pancake_01", "Newshop_Lavender_Cream_Tart_01", "Newshop_Lavender_Pastry_Roll_01", "Newshop_Lobster_Sunrise_Pancake_01", "Newshop_Mango_01", "Newshop_Mango_Berry_Scoop_01", "Newshop_Mango_Blossom_01", "Newshop_Mango_Cooler_01", "Newshop_Mango_Marigold_Bagel_01", "Newshop_Mango_Mint_Truffle_01", "Newshop_Marigold_01", "Newshop_Marigold_Pastry_Twist_01", "Newshop_Milk_Ganache_01", "Newshop_Mint_Custard_Tart_01", "Newshop_Mod_Canvas_Purse_01", "Newshop_Mod_Wool_Dress_01", "Newshop_Orange_Blossom_01", "Newshop_Orange_Cream_Bagel_01", "Newshop_Orange_Farm_Figurine_01", "Newshop_Oranges_01", "Newshop_Pearl_Outfit_01", "Newshop_Pineapple_01", "Newshop_Pineapple_Bagel_Pie_01", "Newshop_Pineapple_Blossom_01", "Newshop_Pineapple_Cranberry_Tart_01", "Newshop_Pineapple_Pie_01", "Newshop_Pom_Cream_Bagel_01", "Newshop_Pomegranate_01", "Newshop_Pomegranate_Aroma_Soap_01", "Newshop_Pomegranate_Perfume_Oil_01", "Newshop_Puff_Pastry_Flowers_01", "Newshop_Quartz_Aroma_Stone_01", "Newshop_Reaper_Crunch_Fries_01", "Newshop_Reaper_Pepper_Rub_01", "Newshop_Reaper_Punch_01", "Newshop_Retro_Knit_Coat_01", "Newshop_Ruby_Berry_Refresher_01", "Newshop_Salted_Coffee_Pancake_01", "Newshop_Salted_Lavender_Scoop_01", "Newshop_Sea_Brew_Bonbon_01", "Newshop_Sea_Clam_Taco_01", "Newshop_Sea_Salt_Truffle_01", "Newshop_Sea_Surf_Rub_01", "Newshop_Shell_Perfume_Compact_01", "Newshop_Shell_Thread_01", "Newshop_Soft_Bagel_01", "Newshop_Sorghum_01", "Newshop_Soybeans_01", "Newshop_Spiced_Cranberry_Scoop_01", "Newshop_Spiced_Kiwi_Scoop_01", "Newshop_Spicy_Bass_Pancake_01", "Newshop_Spicy_Spinach_Pie_01", "Newshop_Spinach_Egg_Taco_01", "Newshop_Spinach_Savory_Tart_01", "Newshop_Spinach_Tart_01", "Newshop_Spinach_Tea_Pancake_01", "Newshop_Steamed_Trout_Pie_01", "Newshop_Sunday_Dress_01", "Newshop_Sunflower_01", "Newshop_Sunset_Crochet_Shawl_01", "Newshop_Sweater_Dress_01", "Newshop_Sweet_Barley_Scoop_01", "Newshop_Sweet_Heat_Rub_01", "Newshop_Tealeaves_01", "Newshop_Tin_Feed_Can_01", "Newshop_Tropical_Krill_Pancake_01", "Newshop_Tropical_Spice_Rub_01", "Newshop_Trout_Herb_Tart_01", "Newshop_Vintage_Dress_01", "Newshop_Wasabi_Lavender_Scoop_01", "Newshop_White_Onion_01", "Newshop_Winter_Kitchen_Shawl_01" };


-- gg.setRanges(gg.REGION_ANONYMOUS)
-- gg.searchNumber(";key")
-- gg.getResults(gg.getResultsCount())
-- gg.editAll(";nokey", gg.TYPE_WORD)
-- gg.clearResults()

-- gg.TYPE_DWORD ( int ) = 4
-- gg.TYPE_FLOAT ( float ) = 16
-- gg.TYPE_DOUBLE ( double ) = 64
-- gg.TYPE_BYTE ( bool ) = 1
-- gg.TYPE_QWORD ( long ) = 32

-- gg.refineNumber(999, 16) -- value + type
-- gg.getResults(99)
-- gg.clearResults()
-- gg.editAll(9999,16) -- value + type

-- setValue(0x2ff4dc4 + 0x20, 4, "~A8 MOV X19, XZR")
-- reset(0x2ff4dc4 + 0x20)

-- setHex(0x30efe28, "20 00 80 D2 C0 03 5F D6")
-- reset(0x2ff4dc4 + 0x20)

-- HexPatch("libil2cpp.so", "SVFastFinish", "GetFastFinishCost", "00 00 80 D2 C0 03 5F D6")
-- ResetHexPatch("libil2cpp.so", "SVFastFinish", "GetFastFinishCost")

----------- LIBRARY & ELF HANDLING -----------

-- returns ELF ranges count and the lib ranges
ORIG = {}
I = {}

function getLibIndices(libName)
    local libList = gg.getRangesList(libName)
    local indices = {}

    if not libList or #libList == 0 then
        gg.toast("Error: " .. libName .. " not found")
        return indices, libList
    end

    for i, v in ipairs(libList) do
        if v.state == "Xa" or v.state == "Cd" then
            local elf = {
                {address = v.start, flags = 1},
                {address = v.start + 1, flags = 1},
                {address = v.start + 2, flags = 1},
                {address = v.start + 3, flags = 1}
            }
            elf = gg.getValues(elf)

            local sig = ""
            for j = 1, 4 do
                if elf[j].value > 31 and elf[j].value < 127 then
                    sig = sig .. string.char(elf[j].value)
                else
                    sig = sig .. " "
                end
            end

            if sig:find("ELF") then
                table.insert(indices, i)
            end
        end
    end

    return indices, libList
end


function original()
    local libName = "libil2cpp.so" -- change if needed
    local indices, libList = getLibIndices(libName)
    ORIG = {}
    local xRx = 1

    if #indices == 0 then
        gg.toast("No valid ELF range found for " .. libName)
        return
    end

    for _, idx in ipairs(indices) do
        local baseAddr = libList[idx].start
        for i, v in ipairs(I) do
            for offset = 0, 12, 4 do
                ORIG[xRx] = {
                    address = baseAddr + tonumber(v) + offset,
                    flags = 4
                }
                xRx = xRx + 1
            end
        end
    end
end

----------- RESET FUNCTION -----------

function reset(off, libName)
    libName = libName or 'libil2cpp.so'
    local resetCount = 0

    local indices, libList = getLibIndices(libName)
    if #indices == 0 then
        gg.alert("ERR: No ELF ranges found to reset")
        return false
    end

    for _, index in ipairs(indices) do
        local offsetKey = off .. "_" .. index
        if orig[offsetKey] then
            gg.setValues(orig[offsetKey])   -- restore original values
            orig[offsetKey] = nil           -- clear backup if you want one-time reset
            resetCount = resetCount + 1
            gg.toast("Reset index " .. index)
            gg.sleep(200)
        end
    end

    if resetCount == 0 then
        gg.toast("⚠️ Nothing to reset for offset " .. string.format("0x%X", off))
    else
        gg.toast("[" .. resetCount .. " indices restored]")
    end

    return true
end
----------- ARM64 INJECT FUNCTION -----------

local bit = bit32

local function toHexBytes(num, bytes)
    local t = {}
    for i = 1, bytes do
        t[i] = string.format("%02X", bit.band(num, 0xFF))
        num = bit.rshift(num, 8)
    end
    return table.concat(t, " ")
end

local function genMinimalAsmHexInt64Signed(v)
    -- v expected as Lua number; we handle negatives by sign-extending 32->64
    -- (bit32 only supports 32-bit math)
    if v >= 0 then
        error("This generator currently handles negatives only")
    end

    -- 32-bit two's complement low part
    local lo32 = bit.band(v, 0xFFFFFFFF)
    local p1 = bit.band(lo32, 0xFFFF)
    local p2 = bit.band(bit.rshift(lo32, 16), 0xFFFF)

    -- sign-extension for upper 32 bits (negative → all ones)
    local p3 = 0xFFFF
    local p4 = 0xFFFF

    local movzBase = 0xD2800000 -- MOVZ X0, #imm16
    local movkBase = 0xF2800000 -- MOVK X0, #imm16, LSL #shift

    local hexInstructions, asmLines = {}, {}

    -- MOVZ for lowest 16 bits
    table.insert(hexInstructions, toHexBytes(bit.bor(movzBase, bit.lshift(p1, 5)), 4))
    table.insert(asmLines, string.format("movx0, #0x%X", p1))

    -- MOVK for upper halves with proper shift encoding: (1/2/3)<<21
    local up = {p2, p3, p4}
    for idx, part in ipairs(up) do
        local hw = bit.lshift(idx, 21)       -- 1→#16, 2→#32, 3→#48
        local instr = bit.bor(movkBase, hw, bit.lshift(part, 5))
        table.insert(hexInstructions, toHexBytes(instr, 4))
        table.insert(asmLines, string.format("movkx0, #0x%X, lsl #%d", part, idx * 16))
    end

    -- RET
    table.insert(hexInstructions, toHexBytes(0xD65F03C0, 4))
    table.insert(asmLines, "ret")

    return table.concat(asmLines, "\n"), table.concat(hexInstructions, " ")
end

function hexG(value)
    if value >= 0 then
        gg.toast("support x32 negetive value only")
        return nil
    end
    local asm, hexStr = genMinimalAsmHexInt64Signed(value)
    --print("Assembly:\n" .. asm .. "\n\nHex:\n" .. hexStr)
    return hexStr
end

-- ======================
-- DOUBLE Support
-- ======================
-- Convert double (Lua number) to IEEE-754 64-bit bits using string pack/unpack
local function doubleToBits(d)
    local packed = string.pack(">d", d)  -- big-endian double
    local b1, b2, b3, b4, b5, b6, b7, b8 = packed:byte(1,8)
    -- construct 64-bit integer from bytes
    local high = bit.bor(bit.lshift(b1, 24), bit.lshift(b2, 16), bit.lshift(b3, 8), b4)
    local low = bit.bor(bit.lshift(b5, 24), bit.lshift(b6, 16), bit.lshift(b7,8), b8)
    return high, low
end

-- Modified genMinimalAsmHex64 for separate high, low 32-bit integers
local function genMinimalAsmHex64FromHiLo(high, low)
    -- Extract 16-bit halfwords from low and high 32-bit parts
    local p = {
        bit.band(low, 0xFFFF),                   -- bits 0-15
        bit.band(bit.rshift(low, 16), 0xFFFF),  -- bits 16-31
        bit.band(high, 0xFFFF),                  -- bits 32-47
        bit.band(bit.rshift(high, 16), 0xFFFF)  -- bits 48-63
    }

    local instrs = {}
    local movzBase, movkBase = 0xD2800000, 0xF2800000

    -- MOVZ (lowest 16 bits)
    table.insert(instrs, {
        bit.bor(movzBase, bit.lshift(p[1], 5)),
        string.format("mov x0, #0x%X", p[1])
    })

    -- MOVK (upper halves if nonzero)
    local shifts = {16, 32, 48}
    for i = 2, 4 do
        if p[i] ~= 0 then
            local hw = bit.lshift(i - 1, 21)
            table.insert(instrs, {
                bit.bor(movkBase, hw, bit.lshift(p[i], 5)),
                string.format("movk x0, #0x%X, lsl #%d", p[i], shifts[i-1])
            })
        end
    end

    -- RET
    table.insert(instrs, {0xD65F03C0, "ret"})

    local asm, hex = {}, {}
    for _, ins in ipairs(instrs) do
        table.insert(asm, ins[2])
        table.insert(hex, toHexBytes(ins[1], 4))
    end

    return table.concat(asm, "\n"), table.concat(hex, " ")
end

function hexGF(f)
    local high, low = doubleToBits(f)
    local asm, hexStr = genMinimalAsmHex64FromHiLo(high, low)
    --print("Assembly:\n" .. asm .. "\n\nHex:\n" .. hexStr)
    return hexStr
end





-- Convert float to 32-bit bits
local function floatToBits(f)
    local sign = (f < 0) and 1 or 0
    if f < 0 then f = -f end
    if f ~= f then return 0x7FC00000 end
    if f == math.huge then return 0x7F800000 end
    if f == -math.huge then return 0xFF800000 end
    local m, e = math.frexp(f)
    e = e + 126
    m = (m * 2 - 1) * 0x800000
    return bit32.bor(bit32.lshift(sign, 31), bit32.lshift(e, 23), bit32.band(m, 0x7FFFFF))
end

-- Generate MOVZ/MOVK + RET instructions
local function genMovSequence(val, is64)
    local parts = {}
    if is64 then
        parts[1] = val & 0xFFFF
        parts[2] = (val >> 16) & 0xFFFF
        parts[3] = (val >> 32) & 0xFFFF
        parts[4] = (val >> 48) & 0xFFFF
    else
        parts[1] = val & 0xFFFF
        parts[2] = (val >> 16) & 0xFFFF
    end

    local seq = {}
    local reg = is64 and "X0" or "W0"

    table.insert(seq, string.format("~A8 MOV %s, #%d", reg, parts[1]))
    local shifts = {16, 32, 48}
    for i = 2, (is64 and 4 or 2) do
        if parts[i] ~= 0 then
            table.insert(seq, string.format("~A8 MOVK %s, #%d, LSL #%d", reg, parts[i], shifts[i-1]))
        end
    end
    table.insert(seq, "~A8 RET")

    return seq
end

-- Main injector (auto-saves original for reset)
function injectAssembly(offset, value, valueType, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local patchCount = 0

    if #indices == 0 then
        gg.alert("No valid ELF ranges found for " .. libName)
        return false
    end

    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        local addr = currentLib + offset
        local offsetKey = offset .. "_" .. index

        local seq = {}

        if type(value) == "boolean" then
            if value then
                seq = {0xD2800020, 0xD65F03C0}  -- MOV X0,#1 ; RET
            else
                seq = {0xD2800000, 0xD65F03C0}  -- MOV X0,#0 ; RET
            end
        elseif valueType == "float" then
            local bits = floatToBits(value)
            seq = genMovSequence(bits, false)
        elseif valueType == "long" then
            seq = genMovSequence(value, true)
        else -- default int
            seq = genMovSequence(value, false)
        end

        -- Backup originals if not already saved
        if not orig[offsetKey] then
            local backup = {}
            for i = 0, (#seq - 1) * 4, 4 do
                table.insert(backup, {address = addr + i, flags = 4})
            end
            orig[offsetKey] = gg.getValues(backup)
        end

        -- Build patch
        local patch = {}
        for i, ins in ipairs(seq) do
            table.insert(patch, {address = addr + (i - 1) * 4, flags = 4, value = ins})
        end
        gg.setValues(patch)

        patchCount = patchCount + 1
        gg.toast("Patched index " .. index)
        gg.sleep(300)
    end

    gg.toast("[" .. patchCount .. " indices injected]")
    return true
end

----------- USAGE EXAMPLES -----------

-- injectAssembly(0x522A24, false)    -- bool false
-- injectAssembly(0x2EB4F0, 999999999)     -- int
-- injectAssembly(0x300000, 3.14, "float")   -- float
-- injectAssembly(0x310000, 123456789123456, "long")  -- 64-bit long
-- reset(0x522A24)   -- restore original at offset

---------- PATCH FUNCTIONS -----------

function setHex(offset, hex, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local patchCount = 0

    if #indices == 0 then
        gg.alert("No valid ELF ranges found for " .. libName)
        return false
    end

    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        local offsetKey = offset .. "_" .. index

        gg.toast("Patching index " .. index .. "...")

        if not orig[offsetKey] then
            local backup, patch, total = {}, {}, 0
            for h in string.gmatch(hex, "%S%S") do
                local addr = currentLib + offset + total
                table.insert(backup, {address = addr, flags = gg.TYPE_BYTE})
                table.insert(patch, {address = addr, flags = gg.TYPE_BYTE, value = tonumber(h,16)})
                total = total + 1
            end
            orig[offsetKey] = gg.getValues(backup)
            gg.setValues(patch)
        else
            local patch, total = {}, 0
            for h in string.gmatch(hex, "%S%S") do
                table.insert(patch, {address = currentLib + offset + total, flags = gg.TYPE_BYTE, value = tonumber(h,16)})
                total = total + 1
            end
            gg.setValues(patch)
        end

        patchCount = patchCount + 1
        gg.sleep(300)
    end

    gg.toast("[" .. patchCount .. " indices patched]")
    return true
end

function setValue(offset, flags, value, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local setCount = 0

    if #indices == 0 then
        gg.alert("No valid ELF ranges found for " .. libName)
        return false
    end

    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        local addr = currentLib + offset
        local offsetKey = offset .. "_" .. index

        gg.toast("Setting value at index " .. index .. "...")

        if not orig[offsetKey] then
            orig[offsetKey] = gg.getValues({{address = addr, flags = flags}})
        end
        gg.setValues({{address = addr, flags = flags, value = value}})

        setCount = setCount + 1
        gg.sleep(300)
    end

    gg.toast("Set values at " .. setCount .. " indices")
    return true
end


function call_void(cc, ref, g, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local callCount = 0
    
    if #indices == 0 then
        gg.alert("No valid indices found for " .. libName)
        return false
    end
    
    for _, index in ipairs(indices) do
        local currentLib = libList[index].start
        
        gg.toast("Applying call_void at index " .. index .. "...")
        
        local p = {}
        p[1] = {address = currentLib + cc, flags = gg.TYPE_DWORD}
        gg.addListItems(p)
        gg.loadResults(p)
        local current_hook = gg.getResults(1)
        
        if not xg[g] then xg[g] = {} end
        if not xg[g][index] then
            gg.loadResults(current_hook)
            xg[g][index] = gg.getResults(gg.getResultsCount())
        end
        gg.clearResults()
        
        local a = currentLib + ref
        local b = currentLib + cc
        local aaaa = a - b
        
        local editVal
        if tonumber(aaaa) < 0 then 
            editVal = ISAOffsetNeg(a, b) 
        else 
            editVal = ISAOffset(aaaa) 
        end
        
        p[1] = {address = currentLib + cc, flags = gg.TYPE_DWORD, value = editVal, freeze = true}
        gg.addListItems(p)
        gg.clearList()
        
        callCount = callCount + 1
        gg.sleep(300)
    end
    
    gg.toast("Applied call_void at " .. callCount .. " indices")
    return true
end

function endhook(cc, g, libName)
    libName = libName or 'libil2cpp.so'
    local indices, libList = getLibIndices(libName)
    local resetCount = 0
    
    if not xg[g] then
        gg.alert("No hooks to reset for group " .. g)
        return false
    end
    
    for index, value in pairs(xg[g]) do
        if libList and libList[index] then
            local currentLib = libList[index].start
            local eh = {}
            eh[1] = {address = currentLib + cc, flags = gg.TYPE_DWORD, value = value[1].value, freeze = true}
            gg.addListItems(eh)
            gg.clearList()
            
            gg.toast("Reset hook at index " .. index)
            resetCount = resetCount + 1
            gg.sleep(300)
        end
    end
    
    if resetCount > 0 then
        gg.toast("Reset " .. resetCount .. " hooks")
    else
        gg.alert("No hooks were reset")
    end
    return true
end

function ISAOffset(aaaa)
    local xHEX = string.format("%X", aaaa)
    if #xHEX > 8 then xHEX = xHEX:sub(#xHEX - 7) end
    return "~A8 B [PC,#0x" .. xHEX .. "]"
end

function ISAOffsetNeg(a, b)
    local xHEX = string.format("%X", b - a)
    if #xHEX > 8 then xHEX = xHEX:sub(#xHEX - 7) end
    return "~A8 B [PC,#-0x" .. xHEX .. "]"
end


local gg = gg;
local ti = gg.getTargetInfo();
local arch = ti.x64;
local p_size = arch and 8 or 4;
local p_type = arch and 32 or 4;

-- helper count
local count = function()
    return gg.getResultsCount();
end;

-- read value
local getvalue = function(address, flags)
    return gg.getValues({{address = address, flags = flags}})[1].value;
end;

-- pointer deref
local ptr = function(address)
    return getvalue(address, p_type);
end;

-- check C-style string at address
local CString = function(address, str)
    local bytes = gg.bytes(str);
    for i = 1, #bytes do
        if (getvalue(address + (i - 1), 1) & 0xFF ~= bytes[i]) then
            return false;
        end;
    end;
    return getvalue(address + #bytes, 1) == 0;
end;

-- Hex patch with ELF index
local savedPatches = {}

function HexPatch(lib, class, method, newHex)
    local results = gg.getRangesList(lib)
    if #results == 0 then
        return false
    end

    local base = results[1].start
    local endAddr = results[1]["end"]

    -- Search for method
    gg.clearResults()
    gg.searchNumber(string.format("Q 00 '%s' 00", method), gg.TYPE_BYTE, false, gg.SIGN_EQUAL, base, endAddr)
    local res = gg.getResults(1)
    if #res == 0 then
        return false
    end

    local addr = res[1].address

    -- Save original bytes if not already saved
    local key = lib .. ":" .. class .. ":" .. method
    if not savedPatches[key] then
        savedPatches[key] = gg.getValues({{address = addr, flags = gg.TYPE_QWORD}})
    end

    -- Write new hex
    local bytes = {}
    local hex = {}
    for b in string.gmatch(newHex, "%S+") do
        table.insert(hex, tonumber(b, 16))
    end
    for i, v in ipairs(hex) do
        bytes[#bytes+1] = {address = addr + (i-1), flags = gg.TYPE_BYTE, value = v}
    end
    gg.setValues(bytes)
    return true
end

function ResetHexPatch(lib, class, method)
    local key = lib .. ":" .. class .. ":" .. method
    if savedPatches[key] then
        gg.setValues(savedPatches[key])
        savedPatches[key] = nil
        return true
    end
    return false
end
gg.clearResults()
--========================
-- GameGuardian Helper Script
--========================

-- Clear all results
function clearAll()
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
end

-- Get all results
function getAll()
    gg.getResults(gg.getResultsCount())
end

-- Search number
function searchNum()
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.searchNumber(x, t)
end

-- Refine search
function refineNum()
    gg.refineNumber(x, t)
end

-- Refine not equal
function refineNot()
    gg.refineNumber(x, t, false, gg.SIGN_NOT_EQUAL)
end

-- Edit all results
function editAll()
    gg.getResults(gg.getResultsCount())
    gg.editAll(x, t)
end

-- Set header for search
function setHeader()
    header = gg.getResults(1)
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.searchNumber(tostring(header[1].value), t)
end

-- Repeat header search
function repeatHeader()
    gg.getResults(gg.getResultsCount())
    gg.clearResults()
    gg.searchNumber(tostring(header[1].value), t)
    gg.getResults(gg.getResultsCount())
end

-- Get header value
function getHeader()
    gg.getResults(gg.getResultsCount())
    header = gg.getResults(1)
end

-- Edit using header
function editHeader()
    gg.editAll(tostring(header[1].value), t)
end

-- Check results
function checkResults()
    local cnt = gg.getResultsCount()
    E = (cnt == 0) and 0 or 1
end

-- Apply offset
function applyOffset()
    local off = tonumber(o)
    local res = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(res) do
        res[i].address = res[i].address + off
        res[i].flags = t
    end
    gg.loadResults(res)
end

-- Apply offset and edit value
function offsetEdit()
    local off = tonumber(o)
    local res = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(res) do
        res[i].address = res[i].address + off
        res[i].flags = t
        res[i].value = header[1].value
    end
    gg.setValues(res)
end

-- Freeze values
function freezeValues()
    local res = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(res) do
        res[i].freeze = true
    end
    gg.addListItems(res)
end

function freeze()
    frz = nil
    frz = gg.getResults(gg.getResultsCount())
    gg.addListItems(frz)
end

-- Cancel operation
function cancel()
    gg.toast("CANCELLED")
end

-- Wait toast
function waitMsg()
    gg.toast("Please Wait..")
end

-- Search pointer
function searchPtr()
    gg.searchPointer(0)
end

-- Check string pointer
function checkString()
    local off = tonumber(o)
    local results = gg.getResults(gg.getResultsCount())
    local addrs, vals = {}, {}

    for i, v in ipairs(results) do
        local ptr = {{address = v.value + off, flags = gg.TYPE_DWORD}}
        local val = gg.getValues(ptr)
        table.insert(addrs, v.address)
        table.insert(vals, val[1].value)
    end

    local matches = {}
    for i, val in ipairs(vals) do
        if val == sv then table.insert(matches, addrs[i]) end
    end

    if #matches > 0 then
        local res = {}
        for i, addr in ipairs(matches) do
            table.insert(res, {address = addr, flags = t})
        end
        gg.loadResults(res)
    else
        gg.alert("No matching addresses found")
        gg.clearResults()
        os.exit()
    end
end

function script()
    y3 = gg.getListItems()
    gg.setRanges(gg.REGION_ANONYMOUS)

    x = y1
    t = 32
    searchNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened")
        return nil
    end

    o = 0x4
    t = 4
    applyOffset()

    x = -1
    t = 4
    refineNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened")
        return nil
    end

    o = 0x4
    t = 4
    applyOffset()
    r1 = gg.getResults(1)
    x1 = r1[1].value

    o = 0x4
    t = 4
    applyOffset()
    r2 = gg.getResults(1)
    x2 = r2[1].value

    clearAll()
    gg.loadResults(y3)

    x = x1
    t = 4
    editAll()

    o = 0x4
    t = 4
    applyOffset()

    x = x2
    t = 4
    editAll()

    o = 0x4
    t = 4
    applyOffset()

    x = pv1
    t = 4
    editAll()

    clearAll()
    gg.alert("FINISH")
end

function scripNew()
    local y3 = gg.getListItems()
    gg.setRanges(gg.REGION_ANONYMOUS)

    x = y1; t = 4; searchNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened [1]")
        return nil
    end
    o = 0x4; t = 4; applyOffset()
    
    x = y2; t = 4; refineNum()
    checkResults()
    if E == 0 then
        gg.alert("Error : Meoww Happened [2]")
        return nil
    end
    o = 0x4; t = 4; applyOffset()

    local r1 = gg.getResults(1)
    local x1 = r1[1].value
    o = 0x4; t = 4; applyOffset()

    local r2 = gg.getResults(1)
    local x2 = r2[1].value
    clearAll()

    gg.loadResults(y3)

    x = x1; t = 4; editAll()
    o = 0x4; t = 4; applyOffset()

    x = x2; t = 4; editAll()
    o = 0x4; t = 4; applyOffset()

    x = pv1; t = 4; editAll()
    clearAll()

    gg.alert("FINISH")
end
--========================
-- Class/Pointer Finder
--========================
function findClass()
gg.clearResults()
gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_OTHER)
gg.searchNumber(":"..x,1)
if gg.getResultsCount()==0 then E=0 return end
local apexu=gg.getResults(gg.getResultsCount())
local filtered={}
for i, v in ipairs(apexu) do
local baseAddr=v.address - 1
local checkVal=gg.getValues({{address=baseAddr, flags=1}})[1].value
if checkVal==0 then
local secondCheckAddr=baseAddr + #x + 1
local secondCheckVal=gg.getValues({{address=secondCheckAddr, flags=1}})[1].value
if secondCheckVal==0 then
filtered[#filtered + 1]={address=secondCheckAddr - #x, flags=1}
end
end
end
if #filtered==0 then E=0 return end
gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_OTHER | gg.REGION_ANONYMOUS)
gg.loadResults(filtered)
gg.searchPointer(0)
if gg.getResultsCount()==0 then E=0 return end
local pointers=gg.getResults(gg.getResultsCount())
local is64=gg.getTargetInfo().x64
local offsets=is64 and {o1=48, o2=56, vt=32} or {o1=24, o2=28, vt=4}
local function find_matches(off1, off2)
local targets={}
local addr_list1, addr_list2={}, {}
for i, v in ipairs(pointers) do
addr_list1[i]={address=v.address + off1, flags=offsets.vt}
addr_list2[i]={address=v.address + off2, flags=offsets.vt}
end
local vals1=gg.getValues(addr_list1)
local vals2=gg.getValues(addr_list2)
for i=1, #vals1 do
if vals1[i].value==vals2[i].value and #tostring(vals1[i].value) >= 8 then
targets[#targets + 1]=vals1[i].value
end
end
return targets
end
local apexp=find_matches(offsets.o1, offsets.o2)
if #apexp==0 then
local retry_o1, retry_o2=(is64 and 32 or 16), (is64 and 40 or 20)
apexp=find_matches(retry_o1, retry_o2)
end
if #apexp==0 then E=0 return end
gg.setRanges(gg.REGION_ANONYMOUS)
gg.clearResults()
local final_results={}
for i, val in ipairs(apexp) do
gg.searchNumber(tonumber(val), offsets.vt)
local found=gg.getResults(gg.getResultsCount())
for j, res in ipairs(found) do
res.name="APEX[GG]v2"
final_results[#final_results + 1]=res
end
gg.clearResults()
end
if #final_results==0 then E=0 return end
local load_list={}
for i, v in ipairs(final_results) do
load_list[#load_list + 1]={address=v.address + o, flags=t}
end
gg.loadResults(load_list)
end

gg.setVisible(false)
gg.alert(
    "────୨ৎ────────୨ৎ────\n" ..
    "🌹 MANAV PREMIUM SCRIPT\n" ..
    "✨ Script By: CheatCode Revolution\n" ..
    "📱 Telegram: @BadLuck_69\n" ..
    "────୨ৎ────────୨ৎ────\n" ..
    "🕹️ : " .. gameName .. "\n" ..
    "📦 : " .. package .. "\n" ..
    "🔖 : " .. version
)

----------- OFFSET LIST ----------------

local offsets = {
    ["30.6.195"] = {
        Remove=0x38670fc, --SVInventory::Remove
Add=0x38658f0, --SVInventory::Add
CanExpandWithCoins=0x3a437c8, --LandExpansionManager::CanExpandWithCoins
GetItemCost=0x3a24444, --ItemManager::GetItemCost
GetFastFinishCost=0x3d17214, --SVFastFinish::GetFastFinishCost
CalculateBuyThroughCost=0x2e6b5d8, --MerchantOfferCell::CalculateBuyThroughCost
GetCraftingTimeMultiplierForBuildingLevel=0x2fd00ac, --UpgradeableBuilding::GetCraftingTimeMultiplierForBuildingLevel
GetCountyFairPointsMultiplierForBuildingLevel=0x2fd011c, --UpgradeableBuilding::GetCountyFairPointsMultiplierForBuildingLevel
get_KnightRequestIntervalSeconds=0x351fda4, --AllianceKnightsManager::get_KnightRequestIntervalSeconds
get_HandsToSend=0x3521db8, --AllianceManager::get_HandsToSend
CreateOffer=0x2a30c78, --SeafarerManager::CreateOffer
GetAutoBuyTime=0x2a2339c, --SeafarerManager::GetAutoBuyTime
GetNumCoopOnlySlotsInUse=0x2a27000, --SeafarerManager::GetNumCoopOnlySlotsInUse
get_getAmountHas=0x2bf5e28, --CoopOrderCard_ViewModel::get_getAmountHas
get_getAmountRequired=0x2bf5fd8, --CoopOrderCard_ViewModel::get_getAmountRequired
get_isCoopOrderExpired=0x2bf63cc, --CoopOrderCard_ViewModel::get_isCoopOrderExpired
canShowThanksGivingStickers=0x389bbe8, --GameExpression::canShowThanksGivingStickers
canShowChristmasStickers=0x389bd24, --GameExpression::canShowChristmasStickers
CanPlayForFree=0x2b6c21c, --GameOfChanceGame::CanPlayForFree
get_totalItemsCount=0x28aa2e8, --ProtoStorageLevel::get_totalItemsCount
get_IsCheaterFixOn=0x2b01000, --BoatRaceV4Context::get_IsCheaterFixOn
get_CheaterTrackingEnabled=0x2af4e14, --BoatRaceV4Context::get_CheaterTrackingEnabled
set_CheaterTrackingEnabled=0x2af4e1c, --BoatRaceV4Context::set_CheaterTrackingEnabled
CheaterFixedScore=0x2b015ec, --BoatRaceV4Context::CheaterFixedScore
get_Suspended=0x340f360, --ZyngaUsersession::get_Suspended
set_Suspended=0x340f368, --ZyngaUsersession::set_Suspended
Start=0x308a3e0, --ZyngaPlayerSuspensionManager::Start
get_amount=0x3986888, --ProtoQuestReward::get_amount
get_GetCurrentLeaguePersonalQuota=0x2ac8f00, --BoatRaceLeagueManager::get_GetCurrentLeaguePersonalQuota
get_personalQuotaCompleted=0x321f97c, --BaseBoatRaceContext::get_personalQuotaCompleted
get_bonusTaskCount=0x321f93c, --BaseBoatRaceContext::get_bonusTaskCount
get_GetBonusTaskSkipPrice=0x2bde34c, --BoatRace_TaskTabViewModel::get_GetBonusTaskSkipPrice
getAmount=0x398786c, --ProtoQuestTask::getAmount
set_MyWeeklyContribution=0x2b2abb4, --CoopOrderHelpContext::set_MyWeeklyContribution
StartCrafting=0x3033f84, --WorkshopManager::StartCrafting
get_inventoryTokens=0x35ba558, --BattlePassManager::get_inventoryTokens
isEntityObstructed=0x36b3bfc, --EntityPlacementController::isEntityObstructed
get_IsAvailable=0x39da69c, --HeroBehavior::get_IsAvailable
OnTamperDetected=0x398f1fc, --SecureVarInt::OnTamperDetected
CurrentUnix=0x3d820dc, --PartnerAnimalTime::CurrentUnix
get_SpinLeft=0x2a60588, --SocialDailyBonusManager::get_SpinLeft
get_groupLimit=0x3985734, --ProtoMarketItem::get_groupLimit
GetAmount=0x3a5e954, --ProtoLootInfoExtensions::GetAmount
GetDropRate=0x3a60b74, --ProtoLootInfoExtensions::GetDropRate
    },
["30.7.196"] = {
Remove=0x38abbf0, --SVInventory::Remove
Add=0x38aa59c, --SVInventory::Add
CanExpandWithCoins=0x3a87ff8, --LandExpansionManager::CanExpandWithCoins
GetItemCost=0x3a68e78, --ItemManager::GetItemCost
GetFastFinishCost=0x3d4ba5c, --SVFastFinish::GetFastFinishCost
CalculateBuyThroughCost=0x2ec5690, --MerchantOfferCell::CalculateBuyThroughCost
GetCraftingTimeMultiplierForBuildingLevel=0x3032648, --UpgradeableBuilding::GetCraftingTimeMultiplierForBuildingLevel
GetCountyFairPointsMultiplierForBuildingLevel=0x30326b8, --UpgradeableBuilding::GetCountyFairPointsMultiplierForBuildingLevel
get_KnightRequestIntervalSeconds=0x356f4c0, --AllianceKnightsManager::get_KnightRequestIntervalSeconds
get_HandsToSend=0x35713bc, --AllianceManager::get_HandsToSend
CreateOffer=0x2a7062c, --SeafarerManager::CreateOffer
GetAutoBuyTime=0x2a631b0, --SeafarerManager::GetAutoBuyTime
GetNumCoopOnlySlotsInUse=0x2a66b7c, --SeafarerManager::GetNumCoopOnlySlotsInUse
get_getAmountHas=0x2c2badc, --CoopOrderCard_ViewModel::get_getAmountHas
get_getAmountRequired=0x2c2bc8c, --CoopOrderCard_ViewModel::get_getAmountRequired
get_isCoopOrderExpired=0x2c2c074, --CoopOrderCard_ViewModel::get_isCoopOrderExpired
canShowThanksGivingStickers=0x38e92f8, --GameExpression::canShowThanksGivingStickers
canShowChristmasStickers=0x38e9434, --GameExpression::canShowChristmasStickers
CanPlayForFree=0x2ba4f44, --GameOfChanceGame::CanPlayForFree
get_totalItemsCount=0x28f05e4, --ProtoStorageLevel::get_totalItemsCount
get_IsCheaterFixOn=0x2b3c31c, --BoatRaceV4Context::get_IsCheaterFixOn
get_CheaterTrackingEnabled=0x2b3049c, --BoatRaceV4Context::get_CheaterTrackingEnabled
set_CheaterTrackingEnabled=0x2b304a4, --BoatRaceV4Context::set_CheaterTrackingEnabled
CheaterFixedScore=0x2b3c8fc, --BoatRaceV4Context::CheaterFixedScore
get_Suspended=0x3464628, --ZyngaUsersession::get_Suspended
set_Suspended=0x3464630, --ZyngaUsersession::set_Suspended
Start=0x30d7fa8, --ZyngaPlayerSuspensionManager::Start
get_amount=0x39beb18, --ProtoQuestReward::get_amount
get_GetCurrentLeaguePersonalQuota=0x2b05608, --BoatRaceLeagueManager::get_GetCurrentLeaguePersonalQuota
get_personalQuotaCompleted=0x32738c4, --BaseBoatRaceContext::get_personalQuotaCompleted
get_bonusTaskCount=0x3273884, --BaseBoatRaceContext::get_bonusTaskCount
get_GetBonusTaskSkipPrice=0x2c1496c, --BoatRace_TaskTabViewModel::get_GetBonusTaskSkipPrice
getAmount=0x39bfa7c, --ProtoQuestTask::getAmount
set_MyWeeklyContribution=0x2b64b28, --CoopOrderHelpContext::set_MyWeeklyContribution
StartCrafting=0x3083a80, --WorkshopManager::StartCrafting
get_inventoryTokens=0x36061f0, --BattlePassManager::get_inventoryTokens
isEntityObstructed=0x36fb094, --EntityPlacementController::isEntityObstructed
get_IsAvailable=0x3a20d80, --HeroBehavior::get_IsAvailable
OnTamperDetected=0x39c73f8, --SecureVarInt::OnTamperDetected
CurrentUnix=0x3dbe838, --PartnerAnimalTime::CurrentUnix
get_SpinLeft=0x2ac26cc, --SocialDailyBonusManager::get_SpinLeft
get_groupLimit=0x39bda84, --ProtoMarketItem::get_groupLimit
GetAmount=0x3aa77d4, --ProtoLootInfoExtensions::GetAmount
GetDropRate=0x3aa8ee0, --ProtoLootInfoExtensions::GetDropRate
}  
}



local version = gg.getTargetInfo().versionName
local currentOffset = offsets[version]
if not currentOffset then
  gg.alert("🤷 Game version is too old or not supported!\n🔖 Current Version: " .. version, "","")
  os.exit()
end

--[[
gg.toast("Bypass Is Running Please Waite...!!")
setValue(currentOffset.Start, 4, "~A8 RET")
setValue(currentOffset.get_Suspended, 4, "~A8 RET")
setValue(currentOffset.set_Suspended, 4, "~A8 RET")
setValue(currentOffset.get_IsCheaterFixOn, 4, "~A8 RET") 
setValue(currentOffset.get_CheaterTrackingEnabled, 4, "~A8 RET")
setValue(currentOffset.set_CheaterTrackingEnabled, 4, "~A8 RET")
setValue(currentOffset.CheaterFixedScore, 4, "~A8 RET")
setValue(currentOffset.OnTamperDetected, 4, "~A8 RET")
--]]

gg.setVisible(false)
  

function Translate(InputText, SystemLangCode, TargetLangCode)
  _ = InputText __ = SystemLangCode ___ = TargetLangCode
  _ = InputText:gsub("\n", "\r\n")
  _ = _:gsub("([^%w])", function(c) return string.format("%%%02X", string.byte(c)) end)
  _ = _:gsub(" ", "%%20")

  Data = gg.makeRequest("https://translate.googleapis.com/translate_a/single?client=gtx&sl="..__.."&tl="..___.."&dt=t&q=".._, 
    {['User-Agent']="Mozilla/5.0"}).content

  if Data == nil then 
    return InputText -- fallback to original text if translation fails
  end

  tData = {} 
  for _ in Data:gmatch("\"(.-)\"") do 
    tData[#tData + 1] = _ 
  end
  return tData[1] or InputText
end

-- 🌐 Language Options
langtable = {
    {"English","en"},
    {"Español","es"},
    {"Türkçe","tr"},
    {"Português","pt"},
    {"Italiano","it"},
    {"Русский","ru"}
}

-- 🌐 Show language selection once at startup
gg.setVisible(false)
local langChoice = gg.choice(
    {
    "🇬🇧 English", 
    "🇪🇸 Español", 
    "🇹🇷 Türkçe", 
    "🇵🇹 Português", 
    "🇮🇹 Italiano", 
    "🇷🇺 Русский"
}, nil, "- SELECT YOUR LANGUAGE -\n_______________________________" )

if not langChoice then 
    langChoice = 1  -- default to English 
end

local TargetLang = langtable[langChoice][2]


----------- PATCH METHODS -----------

function Remove_ON()
    injectAssembly(currentOffset.Remove, true)
    gg.toast("❄️ Freeze Items - ON")
    return true
end

function Remove_OFF()
    reset(currentOffset.Remove)
    gg.toast("❄️ Freeze Items - OFF")
    return nil
end
----------------

function CanExpandWithCoins_ON()
    setHex(currentOffset.CanExpandWithCoins, "20 00 80 D2 C0 03 5F D6")
    gg.toast("💰 Expand With Coins - ON")
    return true
end

function CanExpandWithCoins_OFF()
    setHex(currentOffset.CanExpandWithCoins, "00 00 80 D2 C0 03 5F D6")
    gg.toast("💰 Expand With Coins - OFF")
    return nil
end
----------------

function ItemCost_ON()
    injectAssembly(currentOffset.GetItemCost, false)
    injectAssembly(currentOffset.GetFastFinishCost, false)
    injectAssembly(currentOffset.CalculateBuyThroughCost, false)
    return true
end

function ItemCost_OFF()
    reset(currentOffset.GetItemCost)
    reset(currentOffset.GetFastFinishCost)
    reset(currentOffset.CalculateBuyThroughCost)
    gg.toast("- Hack Disabled -")
    return nil
end
----------------

function FFC_ON()
    setHex(currentOffset.GetCraftingTimeMultiplierForBuildingLevel, "00 00 80 D2 C0 03 5F D6")
    gg.toast("⚡ Fast Farming - ON")
    return true
end
function FFC_OFF()
    reset(currentOffset.GetCraftingTimeMultiplierForBuildingLevel)
    gg.toast("⚡ Fast Farming - OFF")
    return nil
end
----------------

function FHND_ON()
    setHex(currentOffset.get_KnightRequestIntervalSeconds, "00 00 80 D2 C0 03 5F D6")
    gg.toast("💂 Farm Hands Available - ON")
    return true
end
function FHND_OFF()
    reset(currentOffset.get_KnightRequestIntervalSeconds)
    gg.toast("💂 Farm Hands Available - OFF")
    return nil
end
----------------

function SHND_ON()
    setHex(currentOffset.get_HandsToSend, "E0 E1 84 D2 C0 03 5F D6")
    gg.toast("🤝 Send Helping Hands - ON")
    return true
end
function SHND_OFF()
    reset(currentOffset.get_HandsToSend)
    gg.toast("🤝 Send Helping Hands - OFF")
    return nil
end
----------------

function SG_ON()
    setValue(currentOffset.CreateOffer+0x34, 4, "~A8 MOV W22, WZR")
    gg.toast("💰 Sell Goods Free - ON")
    return true
end
function SG_OFF()
    reset(currentOffset.CreateOffer+0x34)
    gg.toast("💰 Sell Goods Free - OFF")
    return nil
end
----------------

function QuestBookFastFinish_ON()
    setHex(currentOffset.getAmount, "00 00 80 D2 C0 03 5F D6")
    gg.toast("📜 Quest Book Fast Finish - ON")
    return true
end

function QuestBookFastFinish_OFF()
    reset(currentOffset.getAmount)
    gg.toast("📜 Quest Book Fast Finish - OFF")
    return nil
end

function MariesOrdersAskButton_ON()
    setHex(currentOffset.get_getAmountHas, "00 00 80 D2 C0 03 5F D6")
    gg.toast("📝 Marie Orders Ask - ON")
    return true
end

function MariesOrdersAskButton_OFF()
    reset(currentOffset.get_getAmountHas)
    gg.toast("📝 Marie Orders Ask - OFF")
    return nil
end

function MariesOrdersSellActive_ON()
    setHex(currentOffset.get_getAmountRequired, "00 00 80 D2 C0 03 5F D6")
    gg.toast("🛒 Marie Orders Sell - ON")
    return true
end

function MariesOrdersSellActive_OFF()
    reset(currentOffset.get_getAmountRequired)
    gg.toast("🛒 Marie Orders Sell - OFF")
    return nil
end

function AutoBuyMarket_ON()
    setHex(currentOffset.GetAutoBuyTime, "20 00 80 D2 C0 03 5F D6")
    gg.toast("🛒 Auto Buy Market - ON")
    return true
end

function AutoBuyMarket_OFF()
    reset(currentOffset.GetAutoBuyTime)
    gg.toast("🛒 Auto Buy Market - OFF")
    return nil
end


function GetCountyFairPointsMultiplierForBuildingLevel_ON()
    I[1] = currentOffset.GetCountyFairPointsMultiplierForBuildingLevel
    original()
    gg.loadResults(ORIG)
    gg.setVisible(false)

    -- Perform the refine search with original known pattern
    local get_ = "-65073176;-117438466;822084671;1409286209"
    x = get_
    t = 4
    refineNum()

    -- Check if results found
    checkResults()
    if E == 0 then
        gg.alert("Error: Something went wrong during search")
        return
    end

    -- Save original values for restore (turning hack OFF)
    Rvrt = gg.getResults(gg.getResultsCount())

    -- Selection menu for multiplier
    local multiplier = {"[1] 50", "[2] 100", "[3] 1000", "[4] 10000", "[5] 100000"}
    local menu4 = gg.choice(multiplier)
    if not menu4 then gg.clearResults() return end

    local edv1 = nil
    if menu4 == 1 then
        edv1 = "1384775680;1923676256;505872384;hC0035FD6"
    elseif menu4 == 2 then
        edv1 = "1384120320;1923631360;505872384;hC0035FD6"
    elseif menu4 == 3 then
        edv1 = "1384120320;1923649344;505872384;hC0035FD6"
    elseif menu4 == 4 then
        edv1 = "1384644608;1923662720;505872384;hC0035FD6"
    elseif menu4 == 5 then
        edv1 = "1384775680;1923676256;505872384;hC0035FD6"
    end

    if edv1 then
        x = edv1
        t = 4
        editAll()
        gg.clearResults()
        gg.toast("Country Fair Workshop Multiplier ON: " .. multiplier[menu4])
    end
  return true
end

function GetCountyFairPointsMultiplierForBuildingLevel_OFF()
   reset(currentOffset.GetCountyFairPointsMultiplierForBuildingLevel)
   gg.toast('Country Fair Workshop Multiplier OFF')
   return nil
end

-- Add these functions for the new feature
function CFF_ON()
    setHex(currentOffset.get_groupLimit, "E0 E1 84 D2 C0 03 5F D6")
    gg.toast("Unlimited Crops/Workshop/Decoration ON")
    -- Add your hack implementation here
    return true
end

function CFF_OFF()
    reset(currentOffset.get_groupLimit)
    gg.toast("Unlimited Crops/Workshop/Decoration OFF")
    -- Add your hack removal implementation here
    return nil
end


function WorkshopsCraftingAmount_ON()
    ::SELECT::
    local pr1 = gg.prompt({'Input Amount (1~65535)'}, nil, {[1] = 'number'})
    if pr1 == nil then return end
    if tostring(pr1[1]) == "" then return end
    if type(tonumber(pr1[1])) ~= "number" then
        gg.alert("INPUT VALUE")
        return
    end
    if tonumber(pr1[1]) < 1 or tonumber(pr1[1]) > 65535 then
        gg.alert("INPUT VALUE 1~65535")
        return
    end

    local pv1 = tonumber(pr1[1])
    local y1 = 65536
    local mth1 = pv1 / y1
    local mth2 = math.floor(mth1) * y1
    local mth3 = pv1 - mth2
    local x2 = string.format("%X", mth3)
    local edv1 = "~A8 MOV W22, #0x" .. x2

    -- Set the offset for the hack (replace 0x29CC844+0x38 with actual offset if needed)
    I[1] = currentOffset.WorkshopsCraftingAmount+0x38

    original()
    gg.loadResults(ORIG)

    -- Search and refine to find the target instruction to patch
    local sv1 = 704840694
    x = sv1
    t = 4
    refineNum()

    checkResults()
    if E == 0 then
        gg.alert("Error: Could not find the pattern to patch")
        return
    end

    -- Save original results to RVT8 for restoring later
    RVT8 = gg.getResults(gg.getResultsCount())

    -- Patch all results with the constructed hex command
    x = edv1
    t = 4
    editAll()

    gg.clearResults()
    gg.toast("Workshops Crafting Amount ON")
    return true
end

function WorkshopsCraftingAmount_OFF()
    if RVT8 then
        gg.setValues(RVT8)
        gg.toast("Workshops Crafting Amount OFF")
        return nil
    else
        gg.alert("No original values found to restore")
        return true
    end
end

function CoopSlots8_ON()
    setHex(currentOffset.GetNumCoopOnlySlotsInUse, "00 00 80 D2 C0 03 5F D6")
    gg.toast("🎰 8 Co-op Slots - ON")
    return true
end

function CoopSlots8_OFF()
    reset(currentOffset.GetNumCoopOnlySlotsInUse)
    gg.toast("🎰 8 Co-op Slots - OFF")
    return nil
end

function UnlockChatEmoji_ON()
    setValue(currentOffset.canShowThanksGivingStickers+0x20, 4, "~A8 MOV X19, XZR")
    setValue(currentOffset.canShowChristmasStickers+0x20, 4, "~A8 MOV X19, XZR")
    gg.toast("💬 Chat Emoji Unlocked - ON")
    return true
end

function UnlockChatEmoji_OFF()
    reset(currentOffset.canShowThanksGivingStickers+0x20)
    reset(currentOffset.canShowChristmasStickers+0x20)
    gg.toast("💬 Chat Emoji - OFF")
    return nil
end


function ProspectorCornerFreePlay_ON()
    setHex(currentOffset.CanPlayForFree, "20 00 80 D2 C0 03 5F D6")
    gg.toast("🆓 Prospector Free Play - ON")
    return true
end

function ProspectorCornerFreePlay_OFF()
    reset(currentOffset.CanPlayForFree)
    gg.toast("🆓 Prospector Free Play - OFF")
    return nil
end

function SetBarnSeaway_ON()
    local pr = gg.prompt({'Set Seaway Barn Capacity (Negative or 1~99999)'}, nil, {[1] = 'number'})
    if pr == nil then return end

    local userInput = tonumber(pr[1])
    if userInput == nil then
        gg.alert("Invalid input")
        return
    end

    -- Accept either negative or positive within allowed range
    if userInput >= 1 and userInput <= 99999 then
        -- Positive number branch: normal 32-bit int inject
        injectAssembly(currentOffset.get_totalItemsCount, userInput) -- 32-bit int inject
        gg.toast("📦 Set Barn Seaway: " .. userInput)
    elseif userInput < 0 then
        -- Negative number branch: generate hex patch via hexG & setHex
        local hexValue = hexG(userInput)
        if hexValue then
            setHex(currentOffset.get_totalItemsCount, hexValue)
            gg.toast("- Set Barn Seaway (Negative) patched -")
        else
            gg.alert("Error generating hex for negative value")
            return
        end
    else
        -- Invalid input
        gg.alert("INPUT VALUE Negative or 1~99999 only")
        return
    end

    return true
end


function SetBarnSeaway_OFF()
    reset(currentOffset.get_totalItemsCount)
    gg.toast("📦 Set Barn Seaway - OFF")
    return nil
end


function BonusTaskPoints_ON()
  local input = gg.prompt({'Enter Bonus Task Points (1~2000000):'}, nil, {[1] = 'number'})
  if input == nil then return end -- user cancelled
  local bonusValue = tonumber(input[1])
  if not bonusValue or bonusValue < 1 or bonusValue > 2000000 then
    gg.alert("Invalid input! Please enter a number between 1 and 2000000.")
    return
  end
  injectAssembly(currentOffset.get_amount, bonusValue)
  gg.toast("- ⛵ (BR) BONUS TASK POINTS set to " .. bonusValue .. " -")
  return true
end

function BonusTaskPoints_OFF()
  reset(currentOffset.get_amount)
  gg.toast("- ⛵ (BR) BONUS TASK POINTS Disabled -")
  return nil
end

function UnlimitedBRDiscardTask_ON()
  local menu = gg.choice({
    "[ + ] Default Mode",
    "[ + ] Unlimited Task",
    "[ + ] Bonus Mode",
  }, nil, "- Set BR Task Limit -")
  
  if menu == 1 then
    setHex(currentOffset.get_personalQuotaCompleted, "00 00 80 D2 C0 03 5F D6")
    gg.toast("- Default Task Enabled -")
  elseif menu == 2 then
    setHex(currentOffset.get_personalQuotaCompleted, "00 83 9F D2 E0 FF BF F2 E0 FF DF F2 E0 FF FF F2 C0 03 5F D6")
    gg.toast("- Unlimited Task Enabled -")
  elseif menu == 3 then
    setHex(currentOffset.get_personalQuotaCompleted, "00 02 80 D2 C0 03 5F D6")
    gg.toast("- Bonus Mode Enabled -")
  else
    gg.toast("- No Mode Selected -")
    return nil
  end
  return nil
end


function UnlimitedBRDiscardTask_OFF()
  reset(currentOffset.get_personalQuotaCompleted)
  gg.toast("- Unlimited BR Discard Task Disabled -")
  return nil
end

function EnterBonusMode_ON()
    injectAssembly(currentOffset.get_personalQuotaCompleted, 16)
    gg.toast("- ⛵ (BR) Enter Bonus Mode Enabled -")
    return true
end

function EnterBonusMode_OFF()
    reset(currentOffset.get_personalQuotaCompleted)
    gg.toast("- ⛵ (BR) Enter Bonus Mode Disabled -")
    return nil
end

function BonusTaskSkipPrice_ON()
    injectAssembly(currentOffset.get_GetBonusTaskSkipPrice, false)
    gg.toast("- ⛵ (BR) Bonus Task Skip Price Enabled -")
    return true
end

function BonusTaskSkipPrice_OFF()
    reset(currentOffset.get_GetBonusTaskSkipPrice)
    gg.toast("- ⛵ (BR) Bonus Task Skip Price Disabled -")
    return nil
end


function BoatRaceTaskRequirement_ON()
    injectAssembly(currentOffset.getAmount, 1)
    gg.toast("- ⛵ Boat Race Task Requirement (1) Enabled -")
    return true
end

function BoatRaceTaskRequirement_OFF()
    reset(currentOffset.getAmount)
    gg.toast("- ⛵ Boat Race Task Requirement Disabled -")
    return nil
end


-- Store the latest user selection for proper restoration
local csp_last_custom = {
    get_amount = nil,
    get_personalQuotaCompleted = nil,
    get_bonusTaskCount = nil,
    pointer_patches = {}
}

function CSP_ON()
    -- Coop Bonus Task Points
    local bonus_select = gg.choice({"[ + ] 40", "[ + ] 50", "[ + ] 60"}, nil, "Co-op Bonus Task Points\n__________________________")
    if not bonus_select then return nil end
    local bp = (bonus_select == 1 and 400) or (bonus_select == 2 and 500) or (bonus_select == 3 and 600)

    -- Coop Special Task Points
    local special_select = gg.choice({"[ + ] 150", "[ + ] 200", "[ + ] 250"}, nil, "Co-op Special Task Points\n__________________________")
    if not special_select then return nil end
    local sp = (special_select == 1 and 1500) or (special_select == 2 and 2000) or (special_select == 3 and 2500)

    -- Regular Task Count
    local regular_select = gg.choice({"[ + ] 10", "[ + ] 11", "[ + ] 12", "[ + ] 13", "[ + ] 15", "[ + ] 18"}, nil, "Regular Task Count\n__________________________")
    if not regular_select then return nil end
    local rct_values = {10, 11, 12, 13, 15, 18}
    local dt = rct_values[regular_select]

    -- Patch get_amount (0x3270E7C) with total: (bp*71 + dt*1500 + sp)
    local total = bp * 71 + dt * 1500 + sp
    injectAssembly(currentOffset.get_amount, total)
    csp_last_custom.get_amount = total

    -- Patch get_personalQuotaCompleted (0x2B88C08) with (dt+1)
    injectAssembly(currentOffset.get_personalQuotaCompleted, dt + 1)
    csp_last_custom.get_personalQuotaCompleted = dt + 1

    -- Patch get_bonusTaskCount (0x2B88BC8) with 71 (as in original)
    injectAssembly(currentOffset.get_bonusTaskCount, 71)
    csp_last_custom.get_bonusTaskCount = 71

    -- =============================
    -- BoatRaceV4Context Patching
    -- =============================
    x = "BoatRaceV4Context"
    o = 0xF0
    t = 4
    findClass()
    x = 3
    t = 4
    refineNum()
    checkResults()
    local p1 = gg.getResultCount()
    local q1 = gg.getResults(p1)

    csp_last_custom.pointer_patches = {}

    for i = 1, p1 do
        local addr1 = q1[i].address - 0x2C
        local addr2 = q1[i].address - 0x20
        local addr3 = q1[i].address + 0x28

        local r = {}
        r[1] = {address = addr1, flags = 4, value = 1}
        r[2] = {address = addr2, flags = 4, value = dt}
        r[3] = {address = addr3, flags = 4, value = 72}
        gg.setValues(r)

        csp_last_custom.pointer_patches[#csp_last_custom.pointer_patches + 1] = r
    end

    clearAll()
    gg.alert(string.format(
        "Br Co-op Shoot Point: ON\nPatched with:\nBonus Points: %d\nSpecial Points: %d\nRegular Count: %d",
        bp, sp, dt
    ))
    return true
end

function CSP_OFF()
    -- Reset main offsets
    reset(currentOffset.get_amount)
    reset(currentOffset.get_personalQuotaCompleted)
    reset(currentOffset.get_bonusTaskCount)

    -- Reset pointer-patched addresses
    if csp_last_custom.pointer_patches and #csp_last_custom.pointer_patches > 0 then
        for _, patchset in ipairs(csp_last_custom.pointer_patches) do
            for _, patch in ipairs(patchset) do
                reset(patch.address)
            end
        end
        csp_last_custom.pointer_patches = {}
        gg.alert("Br Co-op Shoot Point: OFF (Restored)")
    else
        gg.toast("Br Co-op Shoot Point: OFF (Nothing to restore)")
    end
    return nil
end

function Deco_ON()
  x = "ProtoDecoration" o = 0x74 t = 4 findClass()
  x = 4 t = 4 refineNum() o = -0x44 t = 4 applyOffset()
  x = "1~999" t = 4 refineNum() o = 0x44 t = 4 applyOffset()
  local rsv1 = gg.getResults(gg.getResultsCount())
  clearAll()
  gg.loadResults(rsv1)
  o = -0x44 t = 4 applyOffset()
  x = 6 t = 4 refineNum()
  o = 0x18 t = 4 applyOffset()
  x = 3 t = 4 refineNum()
  o = -0x20 t = 4 applyOffset()
  local rsv2 = gg.getResults(1)
  local srv1 = rsv2[1].value
  clearAll()
  gg.loadResults(rsv1)
  o = -0x4C t = 4 applyOffset()
  x = srv1 t = 4 editAll()
  o = 0x8 t = 4 applyOffset() x = 4 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 1 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x4 t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x8 t = 4 applyOffset() 
  x = 0 t = 4 editAll()
  o = 0xC t = 4 applyOffset()
  x = 0 t = 4 editAll()
  o = 0x24 t = 4 applyOffset()
  x = 1 t = 4 editAll()
  clearAll()
  gg.toast("- Decoration Unlocked -")
  return true
end


function Deco_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function AHM_ON()
  gg.setRanges(gg.REGION_ANONYMOUS)
  gg.searchNumber("1705391653", gg.TYPE_DWORD)
  gg.getResults(gg.getResultsCount())
  gg.editAll("1705391652", gg.TYPE_DWORD)
  gg.clearResults()
  gg.toast("👁 Hidden Market Items - ON")
  return true
end


function AHM_OFF()
    gg.toast("⚠ Can't turn Off This hack")
    return true
end


strv1=16
strv2=7274563
strv3=7340143
strv4=7471183


function MWS_ON()
  x="CoopOrderHelpContext" 
  o=0x0 t=4 findClass()
  o=0x8 t=4 applyOffset()
  x=0 t=4 refineNum()
  checkResults() 
  if E==0 then 
     gg.alert("Sorry something wrong happened") 
     return nil
  end
  o=0x10 t=32 applyOffset()
  o=0x10 t=32 sv=strv1 checkString()
  o=0x14 t=32 sv=strv2 checkString()
  o=0x18 t=32 sv=strv3 checkString()
  o=0x1C t=32 sv=strv4 checkString()
  o=0xC8 t=4 applyOffset()
  x=0 t=4 editAll()
  clearAll()
  setValue(currentOffset.set_MyWeeklyContribution+0x40, 4, "~A8 MOV W20, #0x64")
  gg.toast("- Marie weekly score enabled -")
  return true
end


function MWS_OFF()
    reset(currentOffset.set_MyWeeklyContribution+0x28)
    gg.toast("- Weekly  Score Disabled-")
    return nil
end



function HPass_ON()
  x="FarmDiaryFeaturePassManager"
  o=0x18 t=1 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x=0 t=1 refineNum()
  x=1 t=1 editAll()
  clearAll()
  gg.alert("🙂 Hairloom Pass Purchased ...\n👉 Now Restart Your Game To See Changes....")
  return true
end


function HPass_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end


function MPass_ON()
  x="MysteryCollectionSeasonPassManager"
  o=0x20 t=1 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x=0 t=1 refineNum()
  x=1 t=1 editAll()
  clearAll()
  gg.alert("🙂 Mystery Master Pass Purchased ...\n👉 Now Restart Your Game To See Changes....")
  return true
end

function MPass_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function ELPass_ON()
  x="BattlePassFeaturePassManager"
  o=0x38 t=4 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x="0~1" t=4 refineNum()
  x=2 t=4 editAll()
  clearAll()
  gg.alert("🙂 Elite Plus Badge Purchased ...\n👉 Now Restart Your Game To See Changes....")
  return true
end

function ELPass_OFF()
    gg.toast("-  Can't turn Off This hack -")
    return true
end

function ELtoken_ON()
  x="BattlePassTask"
  o=0x20 t=4 findClass()
  checkResults() 
  if E==0 then 
     gg.alert("Error : Meoww Happened") 
     return nil 
  end
  x="1~10000" t=4 refineNum()
  x=0 t=4 editAll()
  clearAll()
  gg.alert("🔓 Success.....")
  return true
end


function ELtoken_OFF()
    gg.toast("⚠ Can't turn Off This hack")
    return true
end


function ELItoken_ON()
  local userInput = gg.prompt({"Enter Elit Token (greater than 0):"}, nil, {[1] = "number"})
  if userInput == nil then
    return nil
  end
  local ELInventory = tonumber(userInput[1])
  if not ELInventory or ELInventory <= 0 then
    gg.alert("Invalid input! Please enter a number greater than 0.")
    return
  end
  injectAssembly(currentOffset.get_inventoryTokens, ELInventory)
  gg.toast("🏅 Elite Badge Tokens Set: "..ELInventory)
  return true
end



function ELItoken_OFF()
    reset(currentOffset.get_inventoryTokens)
    gg.toast("🏅 Elite Badge Tokens - OFF")
    return nil
end



function PEA_ON()
  x="EntityPlacementController"
  o=0x31 t=1 findClass()
  x="1" t=1 refineNum()
  x="0" t=1 editAll()
  clearAll()
  injectAssembly(currentOffset.isEntityObstructed, false)
  gg.toast("🔓 Success.....")
  return true
end


function PEA_OFF()
    x="EntityPlacementController"
    o=0x31 t=1 findClass()
    x="0" t=1 refineNum()
    x="1" t=1 editAll()
    clearAll()
    reset(currentOffset.isEntityObstructed)
    gg.toast("📍 Place Entity - OFF")
    return nil
end


function SE_ON()
  x="HoldToEdit"
  o=0x20 t=4 findClass()
  x="0" t=4 refineNum()
  x="1" t=4 editAll()
  clearAll()
  gg.toast("🏷 Sell Anything - ON")
  return true
end


function SE_OFF()
    x="HoldToEdit"
    o=0x20 t=4 findClass()
    x="1" t=4 refineNum()
    x="0" t=4 editAll()
    clearAll()
    gg.toast("🏷 Sell Anything - OFF")
    return nil
end

function UB_ON()
  x="UpgradeableBuilding"
  o=0x20 t=4 findClass()
  x="0~5" t = 4 refineNum()
  x=3 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=4 t=4 refineNum()
  o=-0x4 t=4 applyOffset()
  x=3 t=4 refineNum()
  x=5 t=4 editAll()
  clearAll()
  gg.alert("⛩️ All Farm Building's Are Upgraded..Now Restart Your Game To See Full Changes")
  return true
end


function UB_OFF()
    x="UpgradeableBuilding"
    o=0x20 t=4 findClass()
    x="1~5" t = 4 refineNum()
    x=0 t=4 editAll()
    clearAll()
    gg.toast("⛩ Buildings Downgraded")
    return nil
end

function UC_ON()
  x="ProtoMill"
  o=0x74 t=4 findClass()
  x="1~3" t=4 refineNum()
  rsv1=gg.getResults(gg.getResultsCount())
  clearAll()
  gg.loadResults(rsv1)
  o=-0x44 t=4 applyOffset()
  x=1 t=4 refineNum()
  o=0x48 t=4 applyOffset()
  x=2 t=4 refineNum()
  o=-0x50 t=4 applyOffset()
  rsv2=gg.getResults(1)
  srv1=rsv2[1].value
  clearAll()
  gg.loadResults(rsv1)
  o=-0x4C t=4 applyOffset()
  x=srv1 t=4 editAll()
  o=0x8 t=4 applyOffset()
  x=4 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=1 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x4 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x8 t=4 applyOffset()
  x=0 t=4 editAll()
  o=0xC t=4 applyOffset()
  x=0 t=4 editAll()
  o=0x24 t=4 applyOffset()
  x=1 t=4 editAll()
  clearAll()
  gg.alert("- 🎁 CROPS, ANIMALS, KEY MAKER(WORKSHOPS) ACTIVE -","","")
  return true
end

function UC_OFF()
    gg.toast("⚠ Can't Turn This Hack Off")
    return true
end


function HH_ON()
  injectAssembly(currentOffset.get_IsAvailable, true)
  gg.toast("- Activated -")
  return true
end


function HH_OFF()
    reset(currentOffset.get_IsAvailable)
    gg.toast("💂 Farm Hands Always Available - OFF")
    return nil
end

function MB_ON()
    local inputs = gg.prompt({
        'Enter XP Amount (1~99999):',
        'Enter Timber Amount (1~99999):',
        'Enter Coin Amount (1~99999):'
    }, nil, { [1] = 'number', [2] = 'number', [3] = 'number' })
    
    if inputs == nil then return end -- User cancelled

    local xp, timber, coin = tonumber(inputs[1]), tonumber(inputs[2]), tonumber(inputs[3])

    -- Validation for each input
    local function isValid(num)
        return num and num >= 1 and num <= 99999
    end

    if not isValid(xp) or not isValid(timber) or not isValid(coin) then
        gg.alert("Invalid input! Please enter values between 1 and 99999.")
        return
    end
    x="MerchantOffer"
    o=0x58 t=4 findClass() --xp
    x="1~99999" t=4 refineNum()
    x=xp t=4 editAll()
    clearAll()
    gg.toast("- Xp ["..xp.."]")
    
    x="MerchantOffer"
    o=0x5C t=4 findClass() --timber
    x="1~99999" t=4 refineNum()
    x=timber t=4 editAll()
    clearAll()
    gg.toast("- Timber ["..timber.."]")
    
    x="MerchantOffer"
    o=0x64 t=4 findClass() --coinPrice
    x="1~99999" t=4 refineNum()
    x=coin t=4 editAll()
    clearAll()
    gg.toast("- Coin ["..coin.."]")
    return true
end


function MB_OFF()
    gg.toast("⚠ Can't Restore To Original")
    return nil
end


-- ===== Event Items Helper Functions (credit: Ertan Hancer) =====
local EVI_offsetLength = info.x64 and 0x10 or 0x8
local EVI_protoLootResults = nil
local EVI_RVT1 = nil
local EVI_RVT2 = nil
local EVI_RVT3 = nil
local EVI_xxx = nil
local EVI_dynamicNames = nil
local EVI_initialized = false

function EVI_class()
    gg.clearResults()
    gg.setRanges(gg.REGION_OTHER)
    gg.searchNumber(":"..x, 1)
    if gg.getResultsCount() == 0 then E = 0 return end
    local apexu = gg.getResults(gg.getResultsCount())
    local filtered = {}
    for i, v in ipairs(apexu) do
        local baseAddr = v.address - 1
        local checkVal = gg.getValues({{address = baseAddr, flags = 1}})[1].value
        if checkVal == 0 then
            local secondCheckAddr = baseAddr + #x + 1
            local secondCheckVal = gg.getValues({{address = secondCheckAddr, flags = 1}})[1].value
            if secondCheckVal == 0 then
                filtered[#filtered + 1] = {address = secondCheckAddr - #x, flags = 1}
            end
        end
    end
    if #filtered == 0 then E = 0 return end
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.loadResults(filtered)
    gg.searchPointer(0)
    if gg.getResultsCount() == 0 then E = 0 return end
    local pointers = gg.getResults(gg.getResultsCount())
    local is64 = info.x64
    local offsets = is64 and {o1 = 48, o2 = 56, vt = 32} or {o1 = 24, o2 = 28, vt = 4}
    local function find_matches(off1, off2)
        local targets = {}
        local addr_list1, addr_list2 = {}, {}
        for i, v in ipairs(pointers) do
            addr_list1[i] = {address = v.address + off1, flags = offsets.vt}
            addr_list2[i] = {address = v.address + off2, flags = offsets.vt}
        end
        local vals1 = gg.getValues(addr_list1)
        local vals2 = gg.getValues(addr_list2)
        for i = 1, #vals1 do
            if vals1[i].value == vals2[i].value and #tostring(vals1[i].value) >= 8 then
                targets[#targets + 1] = vals1[i].value
            end
        end
        return targets
    end
    local apexp = find_matches(offsets.o1, offsets.o2)
    if #apexp == 0 then
        local retry_o1, retry_o2 = (is64 and 32 or 16), (is64 and 40 or 20)
        apexp = find_matches(retry_o1, retry_o2)
    end
    if #apexp == 0 then E = 0 return end
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.clearResults()
    local final_results = {}
    for i, val in ipairs(apexp) do
        gg.searchNumber(tonumber(val), offsets.vt)
        local found = gg.getResults(gg.getResultsCount())
        for j, res in ipairs(found) do
            res.name = "APEX[GG]v2"
            final_results[#final_results + 1] = res
        end
        gg.clearResults()
    end
    if #final_results == 0 then E = 0 return end
    local load_list = {}
    for i, v in ipairs(final_results) do
        load_list[#load_list + 1] = {address = v.address + o, flags = t}
    end
    gg.loadResults(load_list)
end

function EVI_refineclassname()
    local pointerSize = (info.x64 and 8 or 4)
    local pointerType = (info.x64 and gg.TYPE_QWORD or gg.TYPE_DWORD)
    local libstart = 0
    local libil2cppXaCdRange
    local metadata
    local searchRanges = {
        ["Ca"] = gg.REGION_C_ALLOC,
        ["A"] = gg.REGION_ANONYMOUS,
        ["O"] = gg.REGION_OTHER,
    }
    local unsignedFixers = {
        [1] = 0xFF, [2] = 0xFFFF, [4] = 0xFFFFFFFF, [8] = 0xFFFFFFFFFFFFFFFF,
    }

    local function toUnsigned(value, size)
        if value < 0 then value = value & unsignedFixers[size] end
        return value
    end

    local function fixAddressForPointer(address, size)
        local remainder = address % size
        return remainder == 0 and address or (address - remainder)
    end

    local targetClass = EVI_targetClassname
    local targetClassLen = #targetClass
    local targetBytes = {string.byte(targetClass, 1, targetClassLen)}

    local function isTargetClass(addr)
        local tt = {}
        for i = 1, targetClassLen + 1 do
            tt[i] = {address = addr + (i - 1), flags = gg.TYPE_BYTE}
        end
        tt = gg.getValues(tt)
        for i = 1, targetClassLen do
            if (tt[i].value & 0xFF) ~= targetBytes[i] then return false end
        end
        return (tt[targetClassLen + 1].value & 0xFF) == 0
    end

    local function get_metadata()
        local ranges = gg.getRangesList("global-metadata.dat")
        if #ranges > 0 then return ranges end
        local allRanges = gg.getRangesList()
        local stringOffsetReq = {}
        for i, val in ipairs(allRanges) do stringOffsetReq[i] = {address = val.start + 0x18, flags = gg.TYPE_DWORD} end
        stringOffsetReq = gg.getValues(stringOffsetReq)
        local checkReq = {}
        for i, val in ipairs(allRanges) do checkReq[i] = {address = val.start + stringOffsetReq[i].value, flags = gg.TYPE_DWORD} end
        checkReq = gg.getValues(checkReq)
        for i, val in ipairs(checkReq) do
            if val.value == 0x6F63736D then return {allRanges[i]} end
        end
        return {}
    end

    local function getMainLib_Xa_Cd_Region()
        local packageName = info.packageName
        local libName = (packageName == "com.mobile.legends") and "liblogic.so" or "libil2cpp.so"
        local libRanges = gg.getRangesList(libName)
        if #libRanges == 0 then return nil end
        local XaCdRange = {["start"] = 0, ["end"] = 0}
        for i, val in ipairs(libRanges) do
            if val.state == "Xa" then
                if XaCdRange.start == 0 then XaCdRange.start = val.start end
                XaCdRange["end"] = val["end"]
            end
        end
        libstart = libRanges[1].start
        return XaCdRange
    end
    libil2cppXaCdRange = getMainLib_Xa_Cd_Region()
    if not libil2cppXaCdRange then gg.alert("libil2cpp not found") return end
    metadata = get_metadata()
    if #metadata == 0 then gg.alert("Metadata not found") return end
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber(";" .. EVI_item, 2)
    local resCount = gg.getResultsCount()
    if resCount == 0 then gg.alert("String " .. EVI_item .. " not found") return end
    local stringObjects = {}
    local off = info.x64 and -0x10 or -0x8
    local maxCount = resCount > 1000000 and 1000000 or resCount
    local step = 50000
    for i = 1, maxCount, step do
        gg.toast("Processing strings: " .. i .. " to " .. math.min(i + step - 1, maxCount) .. " of " .. maxCount .. "...\nPlease wait.")
        local limit = step
        if i + step - 1 > maxCount then
            limit = maxCount - i + 1
        end
        local results = gg.getResults(limit, i - 1)
        local lengthCheck = {}
        for j = 1, limit do
            lengthCheck[j] = {address = results[j].address - 4, flags = gg.TYPE_DWORD}
        end
        lengthCheck = gg.getValues(lengthCheck)
        for j = 1, limit do
            if lengthCheck[j].value == EVI_stringlengthvalue then
                table.insert(stringObjects, {address = lengthCheck[j].address + off, flags = pointerType})
            end
        end
    end
    gg.toast("String processing complete!")
    if #stringObjects == 0 then gg.alert("No strings with length " .. EVI_stringlengthvalue .. " found") return end
    gg.loadResults(stringObjects)
    gg.searchPointer(0)
    if info.x64 then o = EVI_oo t = 32 applyOffset() else o = EVI_oo t = 4 applyOffset() end
    local pointerResults = gg.getResults(gg.getResultsCount())
    if #pointerResults == 0 then gg.alert("No pointers to the string found") return end
    local finalResults = {}
    local headerRequests = {}
    for i, res in ipairs(pointerResults) do
        local fixedPointer = fixAddressForPointer(res.address, pointerSize)
        headerRequests[#headerRequests + 1] = {address = fixedPointer, flags = pointerType}
    end
    local headers = gg.getValues(headerRequests)
    local classRequests = {}
    for i, hdr in ipairs(headers) do
        local parentPtr = hdr.value
        classRequests[#classRequests + 1] = {address = parentPtr + (pointerSize * 2), flags = pointerType}
        classRequests[#classRequests + 1] = {address = parentPtr + (pointerSize * 3), flags = pointerType}
    end
    local classInfo = gg.getValues(classRequests)
    for i = 1, #classInfo, 2 do
        local namePtr = toUnsigned(classInfo[i].value, pointerSize)
        if namePtr > metadata[1].start and namePtr < metadata[1]["end"] then
            if isTargetClass(namePtr) then
                table.insert(finalResults, pointerResults[(i + 1) / 2])
            end
        end
    end
    gg.clearResults()
    gg.loadResults(finalResults)
end

function EVI_getPointedString(pointerAddress)
    local offsetChars = EVI_offsetLength + 4
    if pointerAddress == 0 then return nil end
    local lengthData = gg.getValues({{address = pointerAddress + EVI_offsetLength, flags = gg.TYPE_DWORD}})
    local len = lengthData[1].value
    if len <= 0 or len > 200 then return nil end

    local charTable = {}
    for i = 0, len - 1 do
        table.insert(charTable, {address = pointerAddress + offsetChars + (i * 2), flags = gg.TYPE_WORD})
    end
    charTable = gg.getValues(charTable)
    local str = ""
    for _, val in ipairs(charTable) do
        local charCode = val.value & 0xFFFF
        if charCode > 0 then
            if charCode <= 0x7F then
                str = str .. string.char(charCode)
            elseif charCode <= 0x7FF then
                str = str .. string.char(0xC0 | (charCode >> 6), 0x80 | (charCode & 0x3F))
            else
                str = str .. string.char(0xE0 | (charCode >> 12), 0x80 | ((charCode >> 6) & 0x3F), 0x80 | (charCode & 0x3F))
            end
        end
    end
    return str
end

function EVI_filterstringname()
    local count = gg.getResultsCount()
    local results = gg.getResults(count)
    local pointers = {}

    for i, v in ipairs(results) do
        pointers[i] = {address = v.value + EVI_offsetLength, flags = gg.TYPE_DWORD}
    end

    local values = gg.getValues(pointers)
    local matchingAddresses = {}
    for i, val in ipairs(values) do
        if val.value == EVI_targetLen then
            table.insert(matchingAddresses, results[i].address)
        end
    end

    if #matchingAddresses > 0 then
        local finalResults = {}
        for i, address in ipairs(matchingAddresses) do
            finalResults[i] = {address = address, flags = t}
        end
        gg.loadResults(finalResults)
    else
        gg.alert("No matching addresses found for string length value " .. EVI_targetLen)
        gg.clearResults()
        return false
    end

    local results2 = gg.getResults(gg.getResultsCount())
    local foundVal = nil
    local finalMatchingAddresses = {}

    for _, res in ipairs(results2) do
        if EVI_getPointedString(res.value) == EVI_targetName then
            foundVal = res.value
            table.insert(finalMatchingAddresses, res.address)
            break
        end
    end

    if #finalMatchingAddresses > 0 then
        local finalResults = {}
        for i, address in ipairs(finalMatchingAddresses) do
            finalResults[i] = {address = address, flags = t}
        end
        gg.loadResults(finalResults)

        if info.x64 then
            EVI_x1 = foundVal & 0xFFFFFFFF
            EVI_x2 = (foundVal >> 32) & 0xFFFFFFFF
        else
            EVI_x1 = foundVal
        end
    else
        gg.alert("Could not find string: " .. EVI_targetName)
        return false
    end
    return true
end

function EVI_script()
    local target = tonumber(EVI_pv1)
    local pType = info.x64 and gg.TYPE_QWORD or gg.TYPE_DWORD
    local itemOff = info.x64 and 0x10 or 0x8
    local amountOff = info.x64 and 0x18 or 0xC

    for i, res in ipairs(EVI_protoLootResults) do
        local baseAddr = res.address

        -- Edit item string pointer
        if info.x64 then
            gg.setValues({
                {address = baseAddr + itemOff, flags = gg.TYPE_DWORD, value = EVI_x1},
                {address = baseAddr + itemOff + 0x4, flags = gg.TYPE_DWORD, value = EVI_x2}
            })
        else
            gg.setValues({
                {address = baseAddr + itemOff, flags = gg.TYPE_DWORD, value = EVI_x1}
            })
        end

        -- Bypass ISecureVar<int> _amount
        local p = gg.getValues({{address = baseAddr + amountOff, flags = pType}})
        local secureObj = p[1].value

        if secureObj ~= nil and secureObj ~= 0 then
            local q = gg.getValues({{address = secureObj + 0x20, flags = pType}})
            local partsPtr = q[1].value

            if partsPtr ~= nil and partsPtr ~= 0 then
                local b = gg.getValues({{address = partsPtr + 0x20, flags = gg.TYPE_BYTE}})
                local function ub(n) if n < 0 then return n + 256 else return n end end
                local k0 = ub(b[1].value)

                local encoded = (k0 ~ target) & 0xFF

                gg.setValues({
                    {address = partsPtr + 0x22, flags = gg.TYPE_BYTE, value = encoded},
                    {address = secureObj + 0x38, flags = gg.TYPE_DWORD, value = target},
                    {address = secureObj + 0x40, flags = gg.TYPE_BYTE, value = target}
                })
            end
        end
    end
    clearAll()
    gg.toast("FINISH")
end

-- ===== Main EVI_ON / EVI_OFF Functions =====

function EVI_ON()

    -- Conflict check: if Normal Items hack is active, turn it off first
    if ITM_initialized then
        gg.toast("⚠️ Disabling Normal Items hack first...")
        if ITM_initialized then
            if info.x64 then
                gg.setValues(ITM_RVT1)
                gg.setValues(ITM_RVT2)
                gg.setValues(ITM_RVT3)
            else
                gg.setValues(ITM_RVT1)
                gg.setValues(ITM_RVT2)
            end
        end
        ITM_initialized = false
        ITM_protoLootResults = nil
        ITM_RVT1 = nil
        ITM_RVT2 = nil
        ITM_RVT3 = nil
        ITM_xxx = nil
        if checkList then checkList[47] = nil end
        gg.sleep(300)
    end

    if not EVI_initialized then
        -- Ask source
        local selectfrom = gg.choice({
            "🍎 Apple Tree",
            "💧 Water",
        }, nil, '👇 Get Items From 👇')
        if not selectfrom then return nil end
        if selectfrom == 1 then EVI_item = "Apple_01" end
        if selectfrom == 2 then EVI_item = "Water_01" end

        -- Find ProtoFixedLootInfo via refineclassname
        EVI_targetClassname = "ProtoFixedLootInfo"
        EVI_stringlengthvalue = 8
        if info.x64 then EVI_oo = -0x10 else EVI_oo = -0x8 end
        EVI_refineclassname()

        checkResults()
        if E == 0 then
            gg.alert("Error: Could not find ProtoFixedLootInfo")
            return nil
        end
        EVI_protoLootResults = gg.getResults(gg.getResultsCount())

        -- Get offset values for reset
        if info.x64 then
            o = 0x10 t = 4 applyOffset()
            EVI_RVT1 = gg.getResults(gg.getResultsCount())
            o = 0x4 t = 4 applyOffset()
            EVI_RVT2 = gg.getResults(gg.getResultsCount())
            o = 0x4 t = 4 applyOffset()
            EVI_RVT3 = gg.getResults(gg.getResultsCount())
        else
            checkResults()
            if E == 0 then
                gg.alert("Error: No results after ProtoFixedLootInfo search")
                return nil
            end
            o = 0x8 t = 4 applyOffset()
            EVI_RVT1 = gg.getResults(gg.getResultsCount())
            o = 0x4 t = 4 applyOffset()
            EVI_RVT2 = gg.getResults(gg.getResultsCount())
        end
        clearAll()

        -- Find ProtoInventoryItem class
        x = "ProtoInventoryItem"
        if info.x64 then o = 0x10 t = 32 else o = 0x8 t = 4 end
        EVI_class()

        EVI_xxx = gg.getResults(gg.getResultsCount())
        clearAll()
        gg.loadResults(EVI_xxx)

        -- Extract dynamic item names
        EVI_dynamicNames = {}
        local nameExists = {}

        local maxCount = #EVI_xxx
        local step = 100
        for i = 1, maxCount, step do
            gg.toast("Processing strings: " .. i .. " to " .. math.min(i + step - 1, maxCount) .. " of " .. maxCount .. "...\nPlease wait.")
            local stop = math.min(i + step - 1, maxCount)
            for j = i, stop do
                local res = EVI_xxx[j]
                local str = EVI_getPointedString(res.value)
                if str and str ~= "" then
                    if not nameExists[str] then
                        table.insert(EVI_dynamicNames, str)
                        nameExists[str] = true
                    end
                end
            end
        end
        gg.toast("String processing complete!")

        if #EVI_dynamicNames == 0 then
            gg.alert("Could not extract any string names!")
            return nil
        end
        clearAll()
        EVI_initialized = true
    end

    -- Find the highest event number
    local maxEventNum = -1
    for _, name in ipairs(EVI_dynamicNames) do
        local evNum = string.match(name, "^Event(%d+)")
        if evNum then
            local num = tonumber(evNum)
            if num > maxEventNum then
                maxEventNum = num
            end
        end
    end

    if maxEventNum == -1 then
        gg.alert("No Event items found.")
        return nil
    end

    -- Filter items for highest event AND containing "BNI" or "Intermediate"
    local prefix = "Event" .. tostring(maxEventNum)
    local filteredItems = {}
    for _, name in ipairs(EVI_dynamicNames) do
        if string.sub(name, 1, #prefix) == prefix then
            if string.find(name, "BNI") or string.find(name, "Intermediate") then
                table.insert(filteredItems, name)
            end
        end
    end

    if #filteredItems == 0 then
        gg.alert("No BNI or Intermediate items found for " .. prefix)
        return nil
    end

    -- Sort the filtered items alphabetically
    table.sort(filteredItems, function(a, b) return a:lower() < b:lower() end)

    -- Add Back to Home option
    local itemChoicesEVI = {}
    for _, name in ipairs(filteredItems) do
        table.insert(itemChoicesEVI, name)
    end
    table.insert(itemChoicesEVI, "🏠 Back to Home (OFF)")

    -- Item selection loop
    while true do
        local itemIndex = gg.choice(itemChoicesEVI, nil, "Select Item (" .. prefix .. "):\n────୨ৎ────────୨ৎ────")
        if not itemIndex then 
            EVI_OFF()
            return nil 
        end -- Return to main menu and turn OFF if cancelled

        -- Back to Home
        if itemIndex == #itemChoicesEVI then
            EVI_OFF()
            return nil
        end

        local amountSelected = false
        while not amountSelected do
            local pr1 = gg.prompt({'Input Amount (1~255)'}, nil, {[1] = 'number'})
            if pr1 == nil then 
                break -- Cancelled amount, break to go back to item selection
            end
            if #(pr1[1]) > 0 and tonumber(pr1[1]) and tonumber(pr1[1]) >= 1 and tonumber(pr1[1]) <= 255 then
                EVI_pv1 = pr1[1]
                amountSelected = true
            else
                gg.alert("INPUT VALUE 1~255")
            end
        end

        if amountSelected then
            -- Reset values before applying
            if info.x64 then
                gg.setValues(EVI_RVT1)
                gg.setValues(EVI_RVT2)
                gg.setValues(EVI_RVT3)
            else
                gg.setValues(EVI_RVT1)
                gg.setValues(EVI_RVT2)
            end

            EVI_targetName = filteredItems[itemIndex]
            EVI_targetLen = #EVI_targetName
            gg.toast("Searching for " .. EVI_targetName)

            if info.x64 then t = 32 else t = 4 end
            gg.loadResults(EVI_xxx)
            local ok = EVI_filterstringname()
            if ok then
                EVI_script()
            end

            -- Wait for user to collect item and tap GG again
            while not gg.isVisible(true) do
                gg.sleep(100)
            end
            gg.setVisible(false)
        end
    end
end


function EVI_OFF()
    -- Restore original loot table values (undo the hack)
    if EVI_initialized then
        if info.x64 then
            gg.setValues(EVI_RVT1)
            gg.setValues(EVI_RVT2)
            gg.setValues(EVI_RVT3)
        else
            gg.setValues(EVI_RVT1)
            gg.setValues(EVI_RVT2)
        end
    end
    -- Clear saved list items
    gg.getListItems()
    gg.clearList()
    -- Reset cached data
    EVI_initialized = false
    EVI_protoLootResults = nil
    EVI_RVT1 = nil
    EVI_RVT2 = nil
    EVI_RVT3 = nil
    EVI_xxx = nil
    EVI_dynamicNames = nil
    gg.toast("- Event Items Reset -")
    return nil
end


-- ===== Normal Items Helper (uses EVI hack logic with custom lists) =====
local ITM_offsetLength = info.x64 and 0x10 or 0x8
local ITM_protoLootResults = nil
local ITM_RVT1 = nil
local ITM_RVT2 = nil
local ITM_RVT3 = nil
local ITM_xxx = nil
local ITM_initialized = false

function ITM_class()
    gg.clearResults()
    gg.setRanges(gg.REGION_OTHER)
    gg.searchNumber(":"..x, 1)
    if gg.getResultsCount() == 0 then E = 0 return end
    local apexu = gg.getResults(gg.getResultsCount())
    local filtered = {}
    for i, v in ipairs(apexu) do
        local baseAddr = v.address - 1
        local checkVal = gg.getValues({{address = baseAddr, flags = 1}})[1].value
        if checkVal == 0 then
            local secondCheckAddr = baseAddr + #x + 1
            local secondCheckVal = gg.getValues({{address = secondCheckAddr, flags = 1}})[1].value
            if secondCheckVal == 0 then
                filtered[#filtered + 1] = {address = secondCheckAddr - #x, flags = 1}
            end
        end
    end
    if #filtered == 0 then E = 0 return end
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.loadResults(filtered)
    gg.searchPointer(0)
    if gg.getResultsCount() == 0 then E = 0 return end
    local pointers = gg.getResults(gg.getResultsCount())
    local is64 = info.x64
    local offsets = is64 and {o1 = 48, o2 = 56, vt = 32} or {o1 = 24, o2 = 28, vt = 4}
    local function find_matches(off1, off2)
        local targets = {}
        local addr_list1, addr_list2 = {}, {}
        for i, v in ipairs(pointers) do
            addr_list1[i] = {address = v.address + off1, flags = offsets.vt}
            addr_list2[i] = {address = v.address + off2, flags = offsets.vt}
        end
        local vals1 = gg.getValues(addr_list1)
        local vals2 = gg.getValues(addr_list2)
        for i = 1, #vals1 do
            if vals1[i].value == vals2[i].value and #tostring(vals1[i].value) >= 8 then
                targets[#targets + 1] = vals1[i].value
            end
        end
        return targets
    end
    local apexp = find_matches(offsets.o1, offsets.o2)
    if #apexp == 0 then
        local retry_o1, retry_o2 = (is64 and 32 or 16), (is64 and 40 or 20)
        apexp = find_matches(retry_o1, retry_o2)
    end
    if #apexp == 0 then E = 0 return end
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.clearResults()
    local final_results = {}
    for i, val in ipairs(apexp) do
        gg.searchNumber(tonumber(val), offsets.vt)
        local found = gg.getResults(gg.getResultsCount())
        for j, res in ipairs(found) do
            res.name = "APEX[GG]v2"
            final_results[#final_results + 1] = res
        end
        gg.clearResults()
    end
    if #final_results == 0 then E = 0 return end
    local load_list = {}
    for i, v in ipairs(final_results) do
        load_list[#load_list + 1] = {address = v.address + o, flags = t}
    end
    gg.loadResults(load_list)
end

function ITM_getPointedString(pointerAddress)
    local offsetChars = ITM_offsetLength + 4
    if pointerAddress == 0 then return nil end
    local lengthData = gg.getValues({{address = pointerAddress + ITM_offsetLength, flags = gg.TYPE_DWORD}})
    local len = lengthData[1].value
    if len <= 0 or len > 200 then return nil end

    local charTable = {}
    for i = 0, len - 1 do
        table.insert(charTable, {address = pointerAddress + offsetChars + (i * 2), flags = gg.TYPE_WORD})
    end
    charTable = gg.getValues(charTable)
    local str = ""
    for _, val in ipairs(charTable) do
        local charCode = val.value & 0xFFFF
        if charCode > 0 then
            if charCode <= 0x7F then
                str = str .. string.char(charCode)
            elseif charCode <= 0x7FF then
                str = str .. string.char(0xC0 | (charCode >> 6), 0x80 | (charCode & 0x3F))
            else
                str = str .. string.char(0xE0 | (charCode >> 12), 0x80 | ((charCode >> 6) & 0x3F), 0x80 | (charCode & 0x3F))
            end
        end
    end
    return str
end

function ITM_filterstringname()
    local count = gg.getResultsCount()
    local results = gg.getResults(count)
    local pointers = {}

    for i, v in ipairs(results) do
        pointers[i] = {address = v.value + ITM_offsetLength, flags = gg.TYPE_DWORD}
    end

    local values = gg.getValues(pointers)
    local matchingAddresses = {}
    for i, val in ipairs(values) do
        if val.value == ITM_targetLen then
            table.insert(matchingAddresses, results[i].address)
        end
    end

    if #matchingAddresses > 0 then
        local finalResults = {}
        for i, address in ipairs(matchingAddresses) do
            finalResults[i] = {address = address, flags = t}
        end
        gg.loadResults(finalResults)
    else
        gg.alert("No matching addresses found for string length value " .. ITM_targetLen)
        gg.clearResults()
        return false
    end

    local results2 = gg.getResults(gg.getResultsCount())
    local foundVal = nil
    local finalMatchingAddresses = {}

    for _, res in ipairs(results2) do
        if ITM_getPointedString(res.value) == ITM_targetName then
            foundVal = res.value
            table.insert(finalMatchingAddresses, res.address)
            break
        end
    end

    if #finalMatchingAddresses > 0 then
        local finalResults = {}
        for i, address in ipairs(finalMatchingAddresses) do
            finalResults[i] = {address = address, flags = t}
        end
        gg.loadResults(finalResults)

        if info.x64 then
            ITM_x1 = foundVal & 0xFFFFFFFF
            ITM_x2 = (foundVal >> 32) & 0xFFFFFFFF
        else
            ITM_x1 = foundVal
        end
    else
        gg.alert("Could not find string: " .. ITM_targetName)
        return false
    end
    return true
end

function ITM_script()
    local target = tonumber(ITM_pv1)
    local pType = info.x64 and gg.TYPE_QWORD or gg.TYPE_DWORD
    local itemOff = info.x64 and 0x10 or 0x8
    local amountOff = info.x64 and 0x18 or 0xC

    for i, res in ipairs(ITM_protoLootResults) do
        local baseAddr = res.address

        -- Edit item string pointer
        if info.x64 then
            gg.setValues({
                {address = baseAddr + itemOff, flags = gg.TYPE_DWORD, value = ITM_x1},
                {address = baseAddr + itemOff + 0x4, flags = gg.TYPE_DWORD, value = ITM_x2}
            })
        else
            gg.setValues({
                {address = baseAddr + itemOff, flags = gg.TYPE_DWORD, value = ITM_x1}
            })
        end

        -- Bypass ISecureVar<int> _amount
        local p = gg.getValues({{address = baseAddr + amountOff, flags = pType}})
        local secureObj = p[1].value

        if secureObj ~= nil and secureObj ~= 0 then
            local q = gg.getValues({{address = secureObj + 0x20, flags = pType}})
            local partsPtr = q[1].value

            if partsPtr ~= nil and partsPtr ~= 0 then
                local b = gg.getValues({{address = partsPtr + 0x20, flags = gg.TYPE_BYTE}})
                local function ub(n) if n < 0 then return n + 256 else return n end end
                local k0 = ub(b[1].value)

                local encoded = (k0 ~ target) & 0xFF

                gg.setValues({
                    {address = partsPtr + 0x22, flags = gg.TYPE_BYTE, value = encoded},
                    {address = secureObj + 0x38, flags = gg.TYPE_DWORD, value = target},
                    {address = secureObj + 0x40, flags = gg.TYPE_BYTE, value = target}
                })
            end
        end
    end
    clearAll()
    gg.toast("FINISH")
end

function ITM_ON()

    -- Conflict check: if Event Items hack is active, turn it off first
    if EVI_initialized then
        gg.toast("⚠️ Disabling Event Items hack first...")
        if EVI_initialized then
            if info.x64 then
                gg.setValues(EVI_RVT1)
                gg.setValues(EVI_RVT2)
                gg.setValues(EVI_RVT3)
            else
                gg.setValues(EVI_RVT1)
                gg.setValues(EVI_RVT2)
            end
        end
        EVI_initialized = false
        EVI_protoLootResults = nil
        EVI_RVT1 = nil
        EVI_RVT2 = nil
        EVI_RVT3 = nil
        EVI_xxx = nil
        EVI_dynamicNames = nil
        if checkList then checkList[46] = nil end
        gg.sleep(300)
    end

    if not ITM_initialized then
        -- Ask source
        local selectfrom = gg.choice({
            "🍎 Apple Tree",
            "💧 Water",
        }, nil, '👇 Get Items From 👇')
        if not selectfrom then return nil end
        local ITM_item
        if selectfrom == 1 then ITM_item = "Apple_01" end
        if selectfrom == 2 then ITM_item = "Water_01" end

        -- Find ProtoFixedLootInfo via EVI_refineclassname
        EVI_targetClassname = "ProtoFixedLootInfo"
        EVI_stringlengthvalue = 8
        EVI_item = ITM_item
        if info.x64 then EVI_oo = -0x10 else EVI_oo = -0x8 end
        EVI_refineclassname()

        checkResults()
        if E == 0 then
            gg.alert("Error: Could not find ProtoFixedLootInfo")
            return nil
        end
        ITM_protoLootResults = gg.getResults(gg.getResultsCount())

        -- Get offset values for reset
        if info.x64 then
            o = 0x10 t = 4 applyOffset()
            ITM_RVT1 = gg.getResults(gg.getResultsCount())
            o = 0x4 t = 4 applyOffset()
            ITM_RVT2 = gg.getResults(gg.getResultsCount())
            o = 0x4 t = 4 applyOffset()
            ITM_RVT3 = gg.getResults(gg.getResultsCount())
        else
            checkResults()
            if E == 0 then
                gg.alert("Error: No results after ProtoFixedLootInfo search")
                return nil
            end
            o = 0x8 t = 4 applyOffset()
            ITM_RVT1 = gg.getResults(gg.getResultsCount())
            o = 0x4 t = 4 applyOffset()
            ITM_RVT2 = gg.getResults(gg.getResultsCount())
        end
        clearAll()

        -- Find ProtoInventoryItem class
        x = "ProtoInventoryItem"
        if info.x64 then o = 0x10 t = 32 else o = 0x8 t = 4 end
        ITM_class()

        ITM_xxx = gg.getResults(gg.getResultsCount())
        clearAll()

        ITM_initialized = true
    end

    -- Main category loop
    while true do
        -- Reset values before each new item
        if info.x64 then
            gg.setValues(ITM_RVT1)
            gg.setValues(ITM_RVT2)
            gg.setValues(ITM_RVT3)
        else
            gg.setValues(ITM_RVT1)
            gg.setValues(ITM_RVT2)
        end

        -- Show item category selection with Back to Home
        local categoryChoice = gg.choice({
            "📌 Pin Items",
            "🎒 Game Items",
            "🌊 Sea Items",
            "🏪 Newshop Items",
            "🏠 Back to Home (OFF)",
        }, nil, "📦 Select Item Category:\n────୨ৎ────────୨ৎ────")

        if not categoryChoice then 
            ITM_OFF()
            return nil 
        end  -- cancelled -> turn off and return

        -- Back to Home - turn OFF and return
        if categoryChoice == 5 then
            ITM_OFF()
            return nil
        end

        local selectedList = nil
        local categoryTitle = ""
        if categoryChoice == 1 then
            selectedList = GoC_PinList
            categoryTitle = "📌 Pin Items"
        elseif categoryChoice == 2 then
            selectedList = GoC_ItemList
            categoryTitle = "🎒 Game Items"
        elseif categoryChoice == 3 then
            selectedList = GoC_SeaItemList
            categoryTitle = "🌊 Sea Items"
        elseif categoryChoice == 4 then
            selectedList = itemStringnt
            categoryTitle = "🏪 Newshop Items"
        end

        if not selectedList or #selectedList == 0 then
            gg.alert("Item list is empty!")
        else
            -- Build choice menu with Back button
            local itemChoices = {}
            for i, name in ipairs(selectedList) do
                table.insert(itemChoices, "[ + ] " .. name)
            end
            table.insert(itemChoices, "⬅️ Back to Categories")

            -- Item selection loop (stays in same category)
            local stayInCategory = true
            while stayInCategory do
                local itemIndex = gg.choice(itemChoices, nil, "Select Item (" .. categoryTitle .. "):\n────୨ৎ────────୨ৎ────")

                if not itemIndex then 
                    stayInCategory = false  -- cancelled, go back to categories
                elseif itemIndex == #itemChoices then
                    stayInCategory = false  -- Back to Categories selected
                else
                    local amountSelected = false
                    while not amountSelected do
                        local pr1 = gg.prompt({'Input Amount (1~255)'}, nil, {[1] = 'number'})
                        if pr1 == nil then 
                            break -- Cancelled amount, break to go back to item selection
                        end
                        if #(pr1[1]) > 0 and tonumber(pr1[1]) and tonumber(pr1[1]) >= 1 and tonumber(pr1[1]) <= 255 then
                            ITM_pv1 = pr1[1]
                            amountSelected = true
                        else
                            gg.alert("INPUT VALUE 1~255")
                        end
                    end

                    if amountSelected then
                        -- Reset values before applying new item
                        if info.x64 then
                            gg.setValues(ITM_RVT1)
                            gg.setValues(ITM_RVT2)
                            gg.setValues(ITM_RVT3)
                        else
                            gg.setValues(ITM_RVT1)
                            gg.setValues(ITM_RVT2)
                        end

                        ITM_targetName = selectedList[itemIndex]
                        ITM_targetLen = #ITM_targetName
                        gg.toast("Searching for " .. ITM_targetName)

                        if info.x64 then t = 32 else t = 4 end
                        gg.loadResults(ITM_xxx)
                        local ok = ITM_filterstringname()
                        if ok then
                            ITM_script()
                        end

                        -- Wait for user to collect item and tap GG again
                        while not gg.isVisible(true) do
                            gg.sleep(100)
                        end
                        gg.setVisible(false)
                    end
                end
            end
            -- Back to Categories → continue main loop
        end
    end
end


function ITM_OFF()
    -- Restore original loot table values (undo the hack)
    if ITM_initialized then
        if info.x64 then
            gg.setValues(ITM_RVT1)
            gg.setValues(ITM_RVT2)
            gg.setValues(ITM_RVT3)
        else
            gg.setValues(ITM_RVT1)
            gg.setValues(ITM_RVT2)
        end
    end
    -- Clear saved list items
    gg.getListItems()
    gg.clearList()
    -- Reset cached data
    ITM_initialized = false
    ITM_protoLootResults = nil
    ITM_RVT1 = nil
    ITM_RVT2 = nil
    ITM_RVT3 = nil
    ITM_xxx = nil
    gg.toast("- Normal Items Reset -")
    return nil
end

function OFG_ON()
  x="ProtoPartnerAnimalBreed" 
  o=0x20 t=16 findClass()
  x="70~80" t=16 refineNum()
  x="100000" t=16 editAll()
  clearAll()
  gg.toast("🌾 One Feed Gold - ON")
  return true
end


function OFG_OFF()
    gg.toast("⚠ Can't Restore to Original")
    return true
end

local originalValues = {} -- Store original values here

function MIA_ON()
    local inputs = gg.prompt({
        'Input Amount (1~999):'
    }, nil, {'number'})
    
    if inputs == nil then return nil end -- User cancelled

    local itAmount = tonumber(inputs[1])

    -- Simplified validation
    if not itAmount or itAmount < 1 or itAmount > 999 then
        gg.alert("Invalid input! Please enter values between 1 and 999.")
        return
    end
    
    -- Clear previous values
    originalValues = {}
    
    -- Find class and get results
    x = "MerchantOfferItem" 
    o = 0x18 
    t = 4 
    findClass()
    
    -- Refine to target range and RECORD original values
    x = "1~999" 
    t = 4 
    refineNum()
    
    -- Get results before editing and store original values
    local results = gg.getResults(gg.getResultsCount())
    for i, v in ipairs(results) do
        originalValues[i] = {
            address = v.address,
            flags = v.flags,
            value = v.value,
            freeze = v.freeze
        }
    end
    
    -- Edit to new value
    x = itAmount 
    t = 4 
    editAll()
    
    clearAll()
    gg.toast("- Active -")
    return true
end

function MIA_OFF()
    if #originalValues == 0 then
        gg.alert("No original values stored or hack was not activated!")
        return true
    end
    
    -- Restore original values
    gg.setValues(originalValues)
    gg.toast("Restored to original values")
    return nil
end



function PC_ON()
    gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    local items = { 
        "[ + ] Anchor", 
        "[ + ] Animal Cash", 
        "[ + ] Axes", 
        "[ + ] Blue Ribbon", 
        "[ + ] Bronze Stamp", 
        "[ + ] Dinner Bell", 
        "[ + ] Eddie Certificate", 
        "[ + ] Farm Cup Points", 
        "[ + ] Gold Net", 
        "[ + ] Gold Stamp", 
        "[ + ] Golden Glove", 
        "[ + ] Hook", 
        "[ + ] Marcos Mart Token", 
        "[ + ] Marie Certificate", 
        "[ + ] Mariner Certificate", 
        "[ + ] Mineral", 
        "[ + ] Park Stamps", 
        "[ + ] Rakes", 
        "[ + ] Red Ribbon", 
        "[ + ] Rope", 
        "[ + ] Rubber", 
        "[ + ] Ruby Glove", 
        "[ + ] Sand Dollar", 
        "[ + ] Shears", 
        "[ + ] Silver Stamp", 
        "[ + ] Snack Bell", 
        "[ + ] Speed Seed", 
        "[ + ] The Crown Society", 
        "[ + ] The Melon Mystery Aid Token", 
        "[ + ] Yellow Ribbon",
        "[ + ] Key",
        "[ + ] County Fair Points"
        
    }

    sel2 = gg.choice(items, nil, "💥 Select an item: \n────୨ৎ────────୨ৎ────")
    if not sel2 then
        gg.alert("No item selected")
        return
    end

    pr1 = gg.prompt({"Input Amount"}, nil, {[1] = "number"})
    if not pr1 or not tonumber(pr1[1]) or tonumber(pr1[1]) < 1 then
        gg.alert("Invalid input")
        return nil
    end
    y2 = pr1[1]

    if sel2 == 1 then y1 = -4172143379 end
    if sel2 == 2 then y1 = -2929526377 end
    if sel2 == 3 then y1 = 2583189040429 end
    if sel2 == 4 then y1 = 31141687881 end
    if sel2 == 5 then y1 = -3423685853 end
    if sel2 == 6 then y1 = 838159600732 end
    if sel2 == 7 then y1 = 1423692758 end
    if sel2 == 8 then y1 = -2350909532 end
    if sel2 == 9 then y1 = -2662329848 end
    if sel2 == 10 then y1 = -4211869540 end
    if sel2 == 11 then y1 = -2161124554 end
    if sel2 == 12 then y1 = -4172143378 end
    if sel2 == 13 then y1 = -3227389232 end
    if sel2 == 14 then y1 = -3896863109 end
    if sel2 == 15 then y1 = -3374039300 end
    if sel2 == 16 then y1 = -3633768666 end
    if sel2 == 17 then y1 = -2737649758 end
    if sel2 == 18 then y1 = -2343555106 end
    if sel2 == 19 then y1 = 5319776532 end
    if sel2 == 20 then y1 = -4172143381 end
    if sel2 == 21 then y1 = -2936877243 end
    if sel2 == 22 then y1 = 1403241851 end
    if sel2 == 23 then y1 = -3212264721 end
    if sel2 == 24 then y1 = -2707345160 end
    if sel2 == 25 then y1 = -2858874734 end
    if sel2 == 26 then y1 = -4023434665 end
    if sel2 == 27 then y1 = -2488230316 end
    if sel2 == 28 then y1 = -2674184633 end
    if sel2 == 29 then y1 = -4217367217 end
    if sel2 == 30 then y1 = 1496248903 end

    if sel2 == 31 then 
        gg.setRanges(gg.REGION_ANONYMOUS)
        x = "2576980464000" t = 32 searchNum()
        local count = gg.getResultsCount()
        if count == 0 then
            gg.alert("Error : Meoww Happened [1] - No results found")
            return nil
        end
        o = 0x8 t = 4 applyOffset()
        r1 = gg.getResults(1)
        x1 = r1[1].value
        o = 0x4 t = 4 applyOffset()
        r2 = gg.getResults(1)
        x2 = r2[1].value
        clearAll()
        x = "GameOfChanceReward"
        o = 0x3C t = 4 findClass()
        x = "65536" t = 4 refineNum()
        local count = gg.getResultsCount()
        if count == 0 then
            gg.alert("Error : Meoww Happened [2] - No results found")
            return nil
        end
        o = -0x4 t = 4 applyOffset()
        x = y2 t = 4 editAll()
        o = -0x4 t = 4 applyOffset()
        x = x2 t = 4 editAll()
        o = -0x4 t = 4 applyOffset()
        x = x1 t = 4 editAll()
        clearAll()
        gg.alert("🟡 Open Porspector Corner Now....", "", "")
        return nil
    end
  
    if sel2 == 32 then y1 = -2894676908 end
  
    gg.setRanges(gg.REGION_ANONYMOUS)
    x = y1 t = 32 searchNum()
    local count = gg.getResultsCount()
    if count == 0 then
        gg.alert("Error : Meoww Happened [1] - No results found")
        return nil
    end

    o = 0x8 t = 4 applyOffset()
    r1 = gg.getResults(1)
    x1 = r1[1].value
    o = 0x4 t = 4 applyOffset()
    r2 = gg.getResults(1)
    x2 = r2[1].value
    clearAll()

    x = "GameOfChanceReward"
    o = 0x3C t = 4 findClass()
    x = 65536 t = 4 refineNum()
    count = gg.getResultsCount()
    if count == 0 then
        gg.alert("Error : Meoww Happened [2] - No refined results")
        return nil
    end

    o = -0x4 t = 4 applyOffset()
    x = y2 t = 4 editAll()
    o = -0x4 t = 4 applyOffset()
    x = x2 t = 4 editAll()
    o = -0x4 t = 4 applyOffset()
    x = x1 t = 4 editAll()
    clearAll()

    gg.alert("🟡 Open Porspector Corner Now....", "", "")
    return nil
end


function PC_OFF()
    return nil
end


function CEX_ON()
    injectAssembly(currentOffset.get_isCoopOrderExpired, true)
    gg.toast("- Enabled -")
    return true
end

function CEX_OFF()
    reset(currentOffset.get_isCoopOrderExpired)
    gg.toast("- Disabled -")
    return nil
end


function AWI_ON()
    setHex(currentOffset.CurrentUnix, "E0FF9FD2E0FF9FF2E0FFBFF2E0FFCFF2C0035FD6")
    gg.toast("- 🐷 Enabled -")
    return true
end

function AWI_OFF()
    reset(currentOffset.CurrentUnix)
    gg.toast("- Disabled -")
    return nil
end


function NC_ON()
    gg.alert("@credit - Ertan Hancer\n@ertanhancer", "","")
    
    local choice = gg.alert(
        "📝 TUTORIAL 📝\n-----------------\n" ..
        "1️⃣ Go to settings → rename your name to: 12345678901234567890\n" ..
        "2️⃣ Close settings and choose Step 1 complete\n" ..
        "3️⃣ Then choose Go to Step 2",
        "✅ OK, I understand",
        "✅ Step 1 complete",
        "✅ Go to Step 2"
    )

    -- Step 0: Copy Name  
    if choice == 1 then  
        gg.copyText("12345678901234567890")  
        gg.toast("Name copied 📋")  
        return  
    end  

    -- Step 1: Search & Patch (Always use 63 characters)
    if choice == 2 then  
        local charLength = 63
        gg.setRanges(gg.REGION_ANONYMOUS)  
        gg.searchNumber(";12345678901234567890")  
        o = -0x4 t = 4 applyOffset()  
        x = 20 t = 4 refineNum()  
        x = charLength
        t = 4 editAll()  
        clearAll()  
        gg.alert("✅ Done!\nRestart your game.\nThen choose 'Go to Step 2'.", "OK")  
        return  
    end  

    -- Step 2: Rename with color options
    if choice == 3 then  
        gg.alert("🔑 Step 2: Change Name", "CONTINUE")  

        -- Always use 63 character length
        local nameLength = 63

        -- UTF16 Handling  
        local function isUTF16(flag)  
            return flag and ";" or ":", flag and 2 or 1  
        end  

        -- Color selection menu
        local colorChoice = gg.multiChoice({
            "🌈 Rainbow Color",
            "🔴 Red",
            "🟡 Yellow",
            "🟣 Purple",
            "🟢 Green",
            "🔵 Blue",
            "💖 Pink"
        }, nil, "🎨 Choose Name Color:")

        if not colorChoice then 
            gg.toast("❌ Color selection cancelled")
            return 
        end

        -- Get new name from user (minimum 7 characters)
        local newname = gg.prompt(
            {"Enter new name (min 7 characters):"}, 
            {""}, 
            {"text"}
        )
        
        if not newname or newname[1] == "" then
            gg.toast("❌ No name entered")
            return
        end
        
        -- Validate name length
        if #newname[1] < 7 then
            gg.alert("❌ Name must be at least 7 characters long!")
            return
        end
        
        -- Apply color formatting
        local coloredName = ""
        local colorCode = ""
        
        if colorChoice[1] then -- Rainbow
            local rainbowColors = {"ff0000", "ffa500", "ffff00", "008000", "0000ff", "4b0082", "ee82ee"}
            for i = 1, #newname[1] do
                local colorIndex = ((i-1) % #rainbowColors) + 1
                coloredName = coloredName .. "[" .. rainbowColors[colorIndex] .. "]" .. newname[1]:sub(i, i)
            end
        elseif colorChoice[2] then -- Red
            colorCode = "ff0000"
        elseif colorChoice[3] then -- Yellow
            colorCode = "ffff00"
        elseif colorChoice[4] then -- Purple
            colorCode = "4b0082"
        elseif colorChoice[5] then -- Green
            colorCode = "008000"
        elseif colorChoice[6] then -- Blue
            colorCode = "0000ff"
        elseif colorChoice[7] then -- Pink
            colorCode = "ee82ee"
        end
        
        -- For single colors, apply to all characters
        if colorCode ~= "" then
            for i = 1, #newname[1] do
                coloredName = coloredName .. "[" .. colorCode .. "]" .. newname[1]:sub(i, i)
            end
        end

        -- Replace name with new one  
        local function setNewName(editname, playername)  
            local stringTag, step = isUTF16(playername[2])  
            local results = gg.getResults(gg.getResultsCount())  
            local replace, sizes = {}, {}  
              
            gg.clearResults()  
            for _, res in ipairs(results) do  
                sizes[#sizes+1] = {address = res.address - 0x4, flags = gg.TYPE_WORD}  
                local addr = res.address  
                for i = 1, #editname do  
                    replace[#replace+1] = {address = addr, flags = gg.TYPE_WORD, value = string.byte(editname:sub(i,i))}  
                    addr = addr + step  
                end  
            end  
              
            sizes = gg.getValues(sizes)  
            for i, v in ipairs(sizes) do  
                if v.value == #playername[1] then  
                    v.value = #editname  
                end  
            end  

            gg.setValues(sizes)  
            gg.setValues(replace)  
            gg.alert("✅ New name set: " .. editname)  
        end  

        -- Search for name in memory (automatically search for 12345678901234567890)
        local function findName64(nameLength)  
            local playername = {"12345678901234567890", true}
            local stringTag, step = isUTF16(playername[2])  
            gg.setRanges(gg.REGION_ANONYMOUS)  
            gg.searchNumber(stringTag .. playername[1])  

            if gg.getResultsCount() == 0 then  
                gg.toast("⚠️ Name not found, try again")  
                return  
            end  

            local length = #playername[1]  
            for i = 1, length do  
                gg.refineNumber(stringTag .. playername[1]:sub(1, length))  
                length = length - 1  
            end  

            -- Refinements (your fixed pattern)  
            local refineVals = {3407923, 3538997, 3670071, 3145785}  
            for _, val in ipairs(refineVals) do  
                o = 0x4 t = 4 applyOffset()  
                x = val t = 4 refineNum()  
                gg.sleep(800)  
            end  

            o = -0x14 t = 4 applyOffset()  
            x = nameLength t = 4 refineNum()  
            o = -0x10 t = 4 applyOffset()  
            x = "C351h~FFFF3CAFh" t = 4 refineNum()  
            o = 0x14 t = 2 applyOffset()  

            setNewName(coloredName, playername)  
        end  

        -- Start Step 2  
        findName64(nameLength)  
        gg.toast("Step 2 complete ✅")  
        return  
    end  

    -- Cancel  
    gg.toast("❌ Cancelled")  
    return nil
end


function NC_OFF()
    gg.toast("- Hollyy Meowwwww -")
    return nil
end


function RBM_ON()
    local userInput = gg.prompt(
        { 'Enter Bonus Task Complted (1~100):' },
        nil,
        { [1] = 'number' }
    )

    if userInput == nil then 
        return -- user cancelled input
    end

    local bonusTask = tonumber(userInput[1])

    -- Validation
    if not (bonusTask and bonusTask >= 1 and bonusTask <= 100) then
        gg.alert("Invalid input! Please enter a value between 1 and 100.")
        return
    end

    -- Bonus Task Patch
    gg.alert("- Bonus Task Completed set to [" .. bonusTask .. "]\n- Now Complete Any One Bonus Task To see changes In leaderboard...!!", "OK")
    injectAssembly(currentOffset.get_bonusTaskCount, bonusTask)

    gg.toast("- Bonus Task set to [" .. bonusTask .. "]")
    return true
end

function RBM_OFF()
    reset(currentOffset.get_bonusTaskCount)
    gg.toast("- Restored Bonus Task -")
    return nil
end

function SPN_ON()
    injectAssembly(currentOffset.get_SpinLeft, 9999)
    gg.toast("🎡 Prize Wheel Spins - ON")
    return true
end

function SPN_OFF()
    reset(currentOffset.get_SpinLeft)
    gg.toast("🎡 Prize Wheel Spins - OFF")
    return nil
end


function FHA_ON()
    local input = gg.prompt({'Enter Amount:'}, nil, {[1] = 'number'})
    if input == nil then return end -- user cancelled
    local amount = tonumber(input[1])
    if not amount then
        gg.alert("Invalid input!")
        return
    end
    injectAssembly(currentOffset.GetAmount, amount)
    gg.toast("🎁 Farm Hands Reward: " .. amount .. " - ON")
    return true
end

function FHA_OFF()
    reset(currentOffset.GetAmount)
    gg.toast("🎁 Farm Hands Reward - OFF")
    return nil
end

function FHD_ON()
    -- auto detect ELF indices for libil2cpp.so
    local indices, libList = getLibIndices('libil2cpp.so')
    if #indices == 0 then
        gg.toast("Error: libil2cpp.so ELF index not found")
        return false
    end

    for _, idx in ipairs(indices) do
        local baseAddress = libList[idx].start

        local patchData = {
            {
                address = baseAddress + currentOffset.GetDropRate + 0,
                value = '52800000h',
                flags = 4
            },
            {
                address = baseAddress + currentOffset.GetDropRate + 4,
                value = '72A87F40h',
                flags = 4
            },
            {
                address = baseAddress + currentOffset.GetDropRate + 8,
                value = '1E270000h',
                flags = 4
            },
            {
                address = baseAddress + currentOffset.GetDropRate + 12,
                value = 'D65F03C0h',
                flags = 4
            }
        }

        gg.setValues(patchData)
    end

    gg.toast("🎯 Farm Hands 100% Drop - ON")
    return true
end

function FHD_OFF()
    reset(currentOffset.GetDropRate)
    gg.toast("🎯 Farm Hands Drop - OFF")
    return nil
end


function CCF_ON()
    x = "CardCollectionCardInfo"
    o = 0x18
    t = 4
    findClass()

    x = "0~30000"
    t = 4
    refineNum()

    o = -0x10
    t = 4
    applyOffset()

    x = 0
    t = 4
    refineNum()

    o = 0x18
    t = 4
    applyOffset()

    x = 0
    t = 4
    refineNum()

    checkResults()
    if count == 0 then
        gg.alert("Error : Meoww Happened [2] - No results found")
        return nil
    end

    o = -0x8
    t = 4
    applyOffset()

    x = 100
    t = 4
    editAll()

    clearAll()
    gg.alert("Success ✌️", "")
    return true
end

function CCF_OFF()
    gg.toast("- Turn OFF -")
    return true
end

function CARD_ON()
    x = "CardCollectionManager"
    o = 0x68
    t = 1
    findClass()
    x="1" t=1 refineNum()
    x="0" t=1 editAll()
    clearAll()
    gg.alert("Success ✌️", "")
    return true
end

function CARD_OFF()
    x = "CardCollectionManager"
    o = 0x68
    t = 1
    findClass()
    x="0" t=1 refineNum()
    x="1" t=1 editAll()
    clearAll()
    gg.toast("Success ✌️")
    return true
end

----------- MENU -----------

gg.setVisible(true)
local menuList = {
	-- 💎 Items & Selling
	"❄️ Freeze All Items",
	"💸 Sell Goods For Free",
	"🏷️ Sell Anything In Farm",

	-- 🚜 Expansions & Buildings
	"🚜 Expand Farm With Coins",
	"🏘️ Upgrade All Buildings",

	-- 🔑 Costs & Keys
	"🔑 Item Cost 0 Key",
	"🎰 Prospector Corner Free Play",

	-- 🐷 Animals
	"🌾 One Feed Gold",
	"⚖️ Show Animal Weigh-in",

	-- 🏕️ Farming & Barn
	"⚡ Fast Farming",
	"📦 Set Barn Seaway",
	"👨‍🌾 Farm Hands Always Available For Use",

	-- 👐 Helpers
	"👋 Request Farmhands",
	"👐 Send Helping Hands",

	-- ⚡ Quest & Orders
	"📖 Quest Book Fast Finish",
	"📝 Maries Orders Ask Button",
	"🛍️ Maries Orders Sell Active",
	"🔢 Marie Order Item Amount",
	"📈 Maries Board Get/Send Xp, Coin, Timber",
	"🏆 Maries Order Weekly Score",

	-- 🛍️ Market
	"💸 Auto Buy (Market)",
	"👁️ Active Hidden Market Items",

	-- 🎪 Fair & Workshops
	"🎪 Country Fair Workshop Multiplier",
	"♾️ Unlimited Crops/Workshop/Decoration",
	"🔨 Workshops Crafting Amount",

	-- 👥 Co-Op
	"👥 Enable 8 Co-Op Slots",
	"⌛ Co-op Order Instant Expire",

	-- 💬 Chat & Social
	"💬 Unlock Chat Emoji",
	"🎨 Edit UserName With Rainbow Colour",

	-- ⛵ Boat Race
	"⛵ (Br) Bonus Task Points",
	"✅ (Br) Set Bonus Task Completed",
	"🎯 (Br) Set Task Limit",
	"⏭️ (Br) Bonus Task Skip Price",
	"1️⃣ (Br) Task Requirement (1)",
	"✨ (Br) Co-op Shoot Point",

	-- 🎡 Wheel & Spins
	"🎡 Prize Wheel Unlimited Spins",

	-- ⭐ Decoration
	"⭐ Unlimited Decoration",

	-- 🎟️ Unlocks & Passes
	"🎟️ Unlock Heirloom Pass",
	"🎫 Unlock Mystery Master Pass",
	"🏅 Unlock Elite Plus Badge",


	-- 🎃 Elite Features
	"✨ Auto Complete Elite Tokens",
	"🎖️ Get Elite Badge Tokens",

	-- 🌍 Place & Entity
	"🌍 Place Entity Anywhere (Water/Land)",

	-- 🌟 Unlimited Resources
	"🌟 Unlimited Crops, Animals, Key Maker",

	-- 🎁 Water Items
	"🎁 Get Event Items",
	"🎒 Get Normal Items",

	"💎 Farm Hands Reward Amount",
	"💯 Farm Hands Reward Chance 100%",
	"🍭 Confection Collection Fast Finish",
	"🃏 Disable Card Collection Pop-up",

	-- ❌ Exit
	"❌ Exit Script...."
}

-- Auto-translate menu (skip if English is selected)
if TargetLang ~= "en" then
    gg.setVisible(false)
    gg.toast("- Translation Started.....-")
    for i, v in ipairs(menuList) do
        menuList[i] = Translate(v, "en", TargetLang)
    end
    gg.toast("- Translation Completed! -")
    gg.setVisible(true)
end

checkList = {
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 
    nil
}

function menu()
    local tsu = gg.multiChoice(menuList, checkList, "🌹 Script By : Manav\n🔰 Bypass Protection Is Running.....\n🧨 Script Mode : Full Safe\n────୨ৎ────────୨ৎ────")
    if not tsu  then
        return
    end
    
    -- All the if statements for each option remain exactly the same...
    -- Only the order of checks has changed to match the new menu organization
    if tsu[1] ~= checkList[1]  then
        if tsu[1]  then
            checkList[1] = Remove_ON()
        else
            checkList[1] = Remove_OFF()
        end
    end
    if tsu[2] ~= checkList[2]  then
        if tsu[2]  then
            checkList[2] = SG_ON()
        else
            checkList[2] = SG_OFF()
        end
    end
    if tsu[3] ~= checkList[3]  then
        if tsu[3]  then
            checkList[3] = SE_ON()
        else
            checkList[3] = SE_OFF()
        end
    end
    if tsu[4] ~= checkList[4]  then
        if tsu[4]  then
            checkList[4] = CanExpandWithCoins_ON()
        else
            checkList[4] = CanExpandWithCoins_OFF()
        end
    end
    if tsu[5] ~= checkList[5]  then
        if tsu[5]  then
            checkList[5] = UB_ON()
        else
            checkList[5] = UB_OFF()
        end
    end
    if tsu[6] ~= checkList[6]  then
        if tsu[6]  then
            checkList[6] = ItemCost_ON()
        else
            checkList[6] = ItemCost_OFF()
        end
    end
    if tsu[7] ~= checkList[7]  then
        if tsu[7]  then
            checkList[7] = ProspectorCornerFreePlay_ON()
        else
            checkList[7] = ProspectorCornerFreePlay_OFF()
        end
    end
    if tsu[8] ~= checkList[8]  then
        if tsu[8]  then
            checkList[8] = OFG_ON()
        else
            checkList[8] = OFG_OFF()
        end
    end
    if tsu[9] ~= checkList[9]  then
        if tsu[9]  then
            checkList[9] = AWI_ON()
        else
            checkList[9] = AWI_OFF()
        end
    end
    if tsu[10] ~= checkList[10]  then
        if tsu[10]  then
            checkList[10] = FFC_ON()
        else
            checkList[10] = FFC_OFF()
        end
    end
    if tsu[11] ~= checkList[11]  then
        if tsu[11]  then
            checkList[11] = SetBarnSeaway_ON()
        else
            checkList[11] = SetBarnSeaway_OFF()
        end
    end
    if tsu[12] ~= checkList[12]  then
        if tsu[12]  then
            checkList[12] = HH_ON()
        else
            checkList[12] = HH_OFF()
        end
    end
    if tsu[13] ~= checkList[13]  then
        if tsu[13]  then
            checkList[13] = FHND_ON()
        else
            checkList[13] = FHND_OFF()
        end
    end
    if tsu[14] ~= checkList[14]  then
        if tsu[14]  then
            checkList[14] = SHND_ON()
        else
            checkList[14] = SHND_OFF()
        end
    end
    if tsu[15] ~= checkList[15]  then
        if tsu[15]  then
            checkList[15] = QuestBookFastFinish_ON()
        else
            checkList[15] = QuestBookFastFinish_OFF()
        end
    end
    if tsu[16] ~= checkList[16]  then
        if tsu[16]  then
            checkList[16] = MariesOrdersAskButton_ON()
        else
            checkList[16] = MariesOrdersAskButton_OFF()
        end
    end
    if tsu[17] ~= checkList[17]  then
        if tsu[17]  then
            checkList[17] = MariesOrdersSellActive_ON()
        else
            checkList[17] = MariesOrdersSellActive_OFF()
        end
    end
    if tsu[18] ~= checkList[18]  then
        if tsu[18]  then
            checkList[18] = MIA_ON()
        else
            checkList[18] = MIA_OFF()
        end
    end
    if tsu[19] ~= checkList[19]  then
        if tsu[19]  then
            checkList[19] = MB_ON()
        else
            checkList[19] = MB_OFF()
        end
    end
    if tsu[20] ~= checkList[20]  then
        if tsu[20]  then
            checkList[20] = MWS_ON()
        else
            checkList[20] = MWS_OFF()
        end
    end
    if tsu[21] ~= checkList[21]  then
        if tsu[21]  then
            checkList[21] = AutoBuyMarket_ON()
        else
            checkList[21] = AutoBuyMarket_OFF()
        end
    end
    if tsu[22] ~= checkList[22]  then
        if tsu[22]  then
            checkList[22] = AHM_ON()
        else
            checkList[22] = AHM_OFF()
        end
    end
    if tsu[23] ~= checkList[23]  then
        if tsu[23]  then
            checkList[23] = GetCountyFairPointsMultiplierForBuildingLevel_ON()
        else
            checkList[23] = GetCountyFairPointsMultiplierForBuildingLevel_OFF()
        end
    end
    -- Add this new condition for county fair fast finish
    if tsu[24] ~= checkList[24]  then
        if tsu[24]  then
            checkList[24] = CFF_ON()
        else
            checkList[24] = CFF_OFF()
        end
    end
    -- Update the indices for all subsequent items (add +1 to each index)
    if tsu[25] ~= checkList[25]  then
        if tsu[25]  then
            checkList[25] = WorkshopsCraftingAmount_ON()
        else
            checkList[25] = WorkshopsCraftingAmount_OFF()
        end
    end
    if tsu[26] ~= checkList[26]  then
        if tsu[26]  then
            checkList[26] = CoopSlots8_ON()
        else
            checkList[26] = CoopSlots8_OFF()
        end
    end
    if tsu[27] ~= checkList[27]  then
        if tsu[27]  then
            checkList[27] = CEX_ON()
        else
            checkList[27] = CEX_OFF()
        end
    end
    if tsu[28] ~= checkList[28]  then
        if tsu[28]  then
            checkList[28] = UnlockChatEmoji_ON()
        else
            checkList[28] = UnlockChatEmoji_OFF()
        end
    end
    if tsu[29] ~= checkList[29]  then
        if tsu[29]  then
            checkList[29] = NC_ON()
        else
            checkList[29] = NC_OFF()
        end
    end
    if tsu[30] ~= checkList[30]  then
        if tsu[30]  then
            checkList[30] = BonusTaskPoints_ON()
        else
            checkList[30] = BonusTaskPoints_OFF()
        end
    end
    if tsu[31] ~= checkList[31]  then
        if tsu[31]  then
            checkList[31] = RBM_ON()
        else
            checkList[31] = RBM_OFF()
        end
    end
    if tsu[32] ~= checkList[32]  then
        if tsu[32]  then
            checkList[32] = UnlimitedBRDiscardTask_ON()
        else
            checkList[32] = UnlimitedBRDiscardTask_OFF()
        end
    end
    if tsu[33] ~= checkList[33]  then
        if tsu[33]  then
            checkList[33] = BonusTaskSkipPrice_ON()
        else
            checkList[33] = BonusTaskSkipPrice_OFF()
        end
    end
    if tsu[34] ~= checkList[34]  then
        if tsu[34]  then
            checkList[34] = BoatRaceTaskRequirement_ON()
        else
            checkList[34] = BoatRaceTaskRequirement_OFF()
        end
    end
    if tsu[35] ~= checkList[35]  then
        if tsu[35]  then
            checkList[35] = CSP_ON()
        else
            checkList[35] = CSP_OFF()
        end
    end
    if tsu[36] ~= checkList[36]  then
        if tsu[36]  then
            checkList[36] = SPN_ON()
        else
            checkList[36] = SPN_OFF()
        end
    end
    if tsu[37] ~= checkList[37]  then
        if tsu[37]  then
            checkList[37] = Deco_ON()
        else
            checkList[37] = Deco_OFF()
        end
    end
    if tsu[38] ~= checkList[38]  then
        if tsu[38]  then
            checkList[38] = HPass_ON()
        else
            checkList[38] = HPass_OFF()
        end
    end
    if tsu[39] ~= checkList[39]  then
        if tsu[39]  then
            checkList[39] = MPass_ON()
        else
            checkList[39] = MPass_OFF()
        end
    end
    if tsu[40] ~= checkList[40]  then
        if tsu[40]  then
            checkList[40] = ELPass_ON()
        else
            checkList[40] = ELPass_OFF()
        end
    end

    if tsu[41] ~= checkList[41]  then
        if tsu[41]  then
            checkList[41] = ELtoken_ON()
        else
            checkList[41] = ELtoken_OFF()
        end
    end
    if tsu[42] ~= checkList[42]  then
        if tsu[42]  then
            checkList[42] = ELItoken_ON()
        else
            checkList[42] = ELItoken_OFF()
        end
    end
    if tsu[43] ~= checkList[43]  then
        if tsu[43]  then
            checkList[43] = PEA_ON()
        else
            checkList[43] = PEA_OFF()
        end
    end
    if tsu[44] ~= checkList[44]  then
        if tsu[44]  then
            checkList[44] = UC_ON()
        else
            checkList[44] = UC_OFF()
        end
    end
    if tsu[45] ~= checkList[45]  then
        if tsu[45]  then
            checkList[45] = EVI_ON()
        else
            checkList[45] = EVI_OFF()
        end
    end
    if tsu[46] ~= checkList[46]  then
        if tsu[46]  then
            checkList[46] = ITM_ON()
        else
            checkList[46] = ITM_OFF()
        end
    end
    if tsu[47] ~= checkList[47]  then
        if tsu[47]  then
            checkList[47] = FHA_ON()
        else
            checkList[47] = FHA_OFF()
        end
    end
    if tsu[48] ~= checkList[48]  then
        if tsu[48]  then
            checkList[48] = FHD_ON()
        else
            checkList[48] = FHD_OFF()
        end
    end
    if tsu[49] ~= checkList[49]  then
        if tsu[49]  then
            checkList[49] = CCF_ON()
        else
            checkList[49] = CCF_OFF()
        end
    end
    if tsu[50] ~= checkList[50]  then
        if tsu[50]  then
            checkList[50] = CARD_ON()
        else
            checkList[50] = CARD_OFF()
        end
    end
    if tsu[51]  then
        gg.getListItems()
        gg.clearList()
        print("╔══════════════════════════════════")
        print("║      ✨ Thank You For Using! ✨ ")
        print("║                                  ")
        print("║      DEV : BadLuck_69            ")
        print("║      OWNER : Manav               ")
        print("╚══════════════════════════════════")
        os.exit()
    end
end

-- Add these functions for
while true  do
    if gg.isVisible(true)  then
        gg.setVisible(false)
        menu()
    end
    gg.sleep(100)
end
